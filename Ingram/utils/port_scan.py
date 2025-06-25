"""端口扫描"""
import socket  # 导入 Python 原生的 socket 模块 (在 gevent patch 后会变为 gevent 的 socket)
# from socket import AF_INET, SOCK_STREAM # 可以更明确地导入常量，可选

from loguru import logger


def port_scan(ip: str, port: str, timeout: int = 1) -> bool:
    logger.debug(f"port_scan: Attempting to scan {ip}:{port} with timeout {timeout}s")
    # port_scan 函数用于检查指定的 IP 地址和端口号是否开放
    # ip: 目标 IP 地址 (字符串)
    # port: 目标端口号 (字符串，内部会转换为整数)
    # timeout: 连接超时时间，单位为秒 (整数，默认为1秒)
    # 返回值: 布尔值，True 表示端口开放，False 表示端口关闭或连接失败

    s = None # 初始化 s 为 None，确保在 finally 中可用性检查
    try:
        # 创建一个 socket 对象
        # family=socket.AF_INET: 指定地址族为 IPv4
        # type=socket.SOCK_STREAM: 指定套接字类型为 TCP (面向连接的套接字)
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

        # 设置套接字操作的超时时间
        # 这会影响后续的 connect_ex 操作，如果连接在指定时间内未完成，则会超时
        s.settimeout(timeout)

        # 尝试连接到目标 IP 和端口
        # connect_ex() 方法类似于 connect()，但它不会在连接失败时抛出异常，而是返回一个错误指示器
        # 如果连接成功，返回 0；如果连接失败，返回一个表示错误原因的 errno 值
        # 需要将端口号从字符串转换为整数
        if s.connect_ex((ip, int(port))) == 0:
            # 如果 connect_ex() 返回 0，表示端口开放且连接成功
            logger.debug(f"port_scan: Success - {ip}:{port} is open.")
            return True
    except socket.timeout:
        # 捕获 socket.timeout 异常，这通常发生在 s.connect_ex() 超时
        logger.debug(f"port_scan: Timeout - {ip}:{port} (timeout: {timeout}s).") # Changed from info to debug
    except OverflowError:
        # 捕获 int(port) 可能因 port 字符串无法转换为有效整数（例如过大）而抛出的 OverflowError
        logger.error(f"端口号 '{port}' 无效或过大，无法进行扫描。") # This is an error, keep as error
    except Exception as e:
        # 捕获其他所有在 socket 操作或类型转换中可能发生的未知异常
        # 例如，如果 IP 地址格式不正确，某些系统上的 socket 操作可能会失败
        # 或者 int(port) 失败（如果 port 不是数字字符串，会是 ValueError，但 Exception 更通用）
        logger.error(f"端口扫描 {ip}:{port} 时发生未知错误: {e}", exc_info=True) # Keep as error
    finally:
        # finally 块确保无论 try 块中发生什么情况 (成功、异常、返回)，socket 都会被关闭
        # 检查 's' 是否已在当前作用域定义并成功创建 (不为 None)
        if s:
            s.close()  # 关闭套接字，释放资源

    # 如果端口未成功连接 (例如超时、连接被拒、发生异常等)，则返回 False
    logger.debug(f"port_scan: Failure or closed - {ip}:{port}.")
    return False
