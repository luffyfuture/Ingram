"""根据指纹给出目标产品信息"""
import hashlib
import re
import requests

from loguru import logger
from lxml import etree


def _parse(req, rule_val):
    # _parse 函数用于判断单个 HTTP 响应 (req) 是否符合给定的指纹规则 (rule_val)
    # rule_val 可能包含多条子规则，通过 '&&' 连接，表示这些子规则必须同时满足 (逻辑与)

    def check_one(item):
        # check_one 函数用于检查单条子规则
        # 子规则的格式通常是 "匹配类型=`匹配值`", 例如 "title=`Login Page`"
        # 使用正则表达式提取匹配类型 (left) 和匹配值 (right)
        match = re.search(r'(.*)=`(.*)`', item)
        if not match: # 如果规则格式不正确，则无法解析，返回 False
            logger.warning(f"无法解析的指纹子规则: {item}")
            return False
        left, right = match.groups()

        if left == 'md5':
            # 如果匹配类型是 md5，则计算响应内容的 MD5 哈希值并与规则中的哈希值比较
            if hashlib.md5(req.content).hexdigest() == right:
                return True
        elif left == 'title':
            # 如果匹配类型是 title，则解析 HTML，获取 <title> 标签内容，并检查是否包含规则中的字符串 (不区分大小写)
            if not req.text: return False # 确保响应体不为空
            try:
                html = etree.HTML(req.text) # 使用 lxml 解析 HTML
                title_elements = html.xpath('//title')
                # html.xpath('//title') 可能返回多个 title 元素，取第一个
                # .xpath('string(.)') 获取元素的文本内容
                if title_elements and right.lower() in title_elements[0].xpath('string(.)').lower():
                    return True
            except Exception as e: # 捕获解析HTML时可能发生的错误
                logger.debug(f"解析HTML title时出错 ({req.url}): {e}")
                return False
        elif left == 'body':
            # 如果匹配类型是 body，则解析 HTML，遍历 <body> 内所有直接子节点
            # 并检查这些节点的文本内容是否包含规则中的字符串 (不区分大小写)
            # 注意: 这种方式可能不会检查嵌套非常深的文本，但对于一般指纹够用
            if not req.text: return False # 确保响应体不为空
            try:
                html = etree.HTML(req.text)
                body_nodes = html.xpath('//body')
                if body_nodes: # 确保 body 节点存在
                    # 检查 body 自身的文本内容 (string(body_nodes[0]))
                    if right.lower() in body_nodes[0].xpath('string(.)').lower():
                        return True
                    # (可选) 如果需要检查子节点，可以取消注释下面的循环
                    # for node in body_nodes[0]: # 遍历 body 的直接子节点
                    #     if right.lower() in node.xpath('string(.)').lower():
                    #         return True
            except Exception as e: # 捕获解析HTML时可能发生的错误
                logger.debug(f"解析HTML body时出错 ({req.url}): {e}")
                return False
        elif left == 'headers':
            # 如果匹配类型是 headers，则遍历响应头中的每一项 (键和值)
            # 检查拼接后的字符串是否包含规则中的字符串 (不区分大小写)
            for header_key, header_value in req.headers.items(): # req.headers.items() 迭代 (key, value) 对
                if right.lower() in (str(header_key) + ": " + str(header_value)).lower(): # 拼接键和值进行匹配，更符合HTTP头格式
                    return True
        elif left == 'status_code':
            # 如果匹配类型是 status_code，则比较响应的状态码是否与规则中的状态码相等
            return int(req.status_code) == int(right)
        return False # 如果以上所有匹配类型都不符合，或者符合类型的条件未满足，则返回 False

    # 使用 all() 函数和 map() 函数来确保 rule_val 中所有 '&&' 分隔的子规则都通过 check_one 的检查
    # rule_val.split('&&') 将规则字符串按 '&&' 分割成子规则列表
    try:
        return all(map(check_one, rule_val.split('&&')))
    except Exception as e: # 捕获在解析 rule_val 或 map 过程中可能发生的错误
        logger.error(f"处理指纹规则 '{rule_val}' 时发生错误: {e}", exc_info=True)
        return False


def fingerprint(ip, port, config):
    # fingerprint 函数用于根据预定义的规则集 (config.rules) 来识别指定 IP 和端口上运行的服务产品
    # ip: 目标 IP 地址
    # port: 目标端口号
    # config: 应用配置实例，包含指纹规则、超时时间、User-Agent 等
    logger.debug(f"fingerprint: Starting fingerprinting for {ip}:{port}")

    req_dict = {}  # 创建一个字典，用于暂存已获取的 HTTP 响应 (req)，以路径为键，避免对同一路径重复请求
    session = requests.session() # 创建一个 requests.Session 对象，可以保持 TCP 连接，提高效率
    # 设置请求头，'Connection': 'close' 表示不使用 HTTP keep-alive，User-Agent 来自配置
    headers = {'Connection': 'close', 'User-Agent': config.user_agent}

    # 遍历配置中定义的所有指纹规则
    for rule in config.rules:
        try:
            # 尝试从 req_dict 缓存中获取针对当前规则路径 (rule.path) 的响应
            req = req_dict.get(rule.path) # Try cache first
            if not req: # 如果缓存中没有，则发送新请求
                # 请求 URL 格式为 http://ip:port/rule.path
                # verify=False 忽略 SSL 证书验证, allow_redirects=False 通常用于指纹识别，避免跳转到非预期页面
                target_url = f"http://{ip}:{port}{rule.path}"
                logger.debug(f"fingerprint: Attempting to GET {target_url} for rule '{rule.product}' (path: {rule.path})")
                req = session.get(target_url, headers=headers, timeout=config.timeout, verify=False, allow_redirects=False)
                logger.debug(f"fingerprint: GET {target_url} status: {req.status_code if req else 'NoResponse'}")

                # 如果当前路径 (rule.path) 不在缓存中，并且响应状态码为 200 (OK) (或根据需求调整)
                # 则将此响应存入缓存 req_dict，供后续具有相同路径的规则使用
                # 考虑只缓存成功或有意义的响应，避免缓存过多错误页面
                if req.status_code == 200 or (300 <= req.status_code < 400) : # 缓存2xx和3xx响应
                    req_dict[rule.path] = req

            # 调用 _parse 函数，判断当前响应 req 是否符合当前规则的指纹值 (rule.val)
            if req and _parse(req, rule.val): # Ensure req is not None before parsing
                logger.debug(f"fingerprint: Match found for {ip}:{port} -> {rule.product} with rule value '{rule.val}' on path '{rule.path}'")
                return rule.product
        except requests.exceptions.RequestException as e: # 捕获 requests 可能抛出的所有请求相关异常
            # 例如 Timeout, ConnectionError 等
            # Ensuring path_to_check is defined for logging, even if req failed early
            path_for_log = rule.path if 'rule' in locals() and hasattr(rule, 'path') else "unknown_path"
            logger.debug(f"fingerprint: RequestException for {ip}:{port}{path_for_log} - {e}") # 使用 debug 级别
        except Exception as e:
            # 捕获其他可能的未知错误，例如解析 HTML 或规则字符串时发生的错误
            path_for_log = rule.path if 'rule' in locals() and hasattr(rule, 'path') else "unknown_path"
            logger.error(f"fingerprint: Unknown error during fingerprinting ({ip}:{port}{path_for_log}): {e}", exc_info=True) # 使用 error 级别并记录堆栈信息

    # 如果遍历完所有规则后都没有匹配成功，则返回 None，表示未能识别出产品
    logger.debug(f"fingerprint: No product identified for {ip}:{port}")
    return None