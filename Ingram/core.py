import os
# from collections import defaultdict # No longer needed in this file
from threading import Thread
import signal
import gevent
import gevent.event
from loguru import logger
from gevent.pool import Pool as geventPool

from .data import Data, SnapshotPipeline
from .pocs import get_poc_dict
# from .utils import color # No longer needed in this file directly
from .utils import common
from .utils import fingerprint
from .utils import port_scan
from .utils.status_bar import StatusBarManager # Modified import
from .utils import timer
from .reporting import ReportGenerator # Import the new ReportGenerator


@common.singleton
class Core:

    def __init__(self, config):
        self.config = config
        self.data = Data(config)  # 数据处理实例
        self.snapshot_pipeline = SnapshotPipeline(config)  # 快照处理管道实例
        self.poc_dict = get_poc_dict(self.config)  # PoC 字典
        self.shutdown_event = gevent.event.Event() # 创建一个 gevent 事件，用于优雅地通知关闭
        self.status_bar_service = StatusBarManager(self) # Instantiate StatusBarManager

    def finish(self):
        # 判断所有任务是否完成（所有目标已扫描，且快照管道中没有待处理或正在处理的任务）
        # self.data.done 是已完成的目标（IP）数量
        # self.data.total 是需要扫描的目标（IP）总数量
        # self.snapshot_pipeline.task_count 是快照管道中当前正在处理或队列中的任务数量
        # 当已完成数量大于等于总数，并且快照任务数为0或更少（理论上不应为负），则认为整体任务完成
        return (self.data.done >= self.data.total) and (self.snapshot_pipeline.task_count <= 0)

    def _signal_handler(self, sig, frame):
        # 信号处理函数，当接收到指定的信号 (如 SIGINT) 时被调用
        logger.warning(f"接收到信号 {sig}，开始优雅关闭...")
        self.shutdown_event.set() # 设置事件，通知其他协程和组件停止工作

    # def report(self): -- Method removed, logic moved to ReportGenerator

    def _process_open_port(self, ip: str, port_str: str):
        """处理已确认开放的端口：指纹识别、PoC验证等。"""
        logger.debug(f"Core._process_open_port: Processing open port {ip}:{port_str}")
        # logger.info(f"{ip} 端口 {port_str} 开放") # This info log is now effectively covered by debug log + subsequent logs

        # 对开放的端口进行指纹识别
        # product 保存识别出的产品名称，如果未识别到则为 None
        logger.debug(f"Core._process_open_port: Calling fingerprint for {ip}:{port_str}")
        product = fingerprint(ip, port_str, self.config) # Pass port_str
        logger.debug(f"Core._process_open_port: Fingerprint result for {ip}:{port_str} -> {product}")

        if product:
            logger.info(f"{ip}:{port_str} 的产品指纹是 {product}") # Keep this info log for identified product
            verified = False  # 标记此服务是否通过了任何 PoC 的验证

            # 遍历该产品对应的所有 PoC (Proof of Concept) 脚本
            logger.debug(f"Core._process_open_port: Starting PoC checks for product '{product}' on {ip}:{port_str}")
            for poc in self.poc_dict.get(product, []): # Use .get for safety
                if self.shutdown_event.is_set():  # 在执行每个 PoC 前，再次检查关闭信号
                    logger.debug(f"Core._process_open_port: PoC 验证 {ip}:{port_str} ({poc.name if hasattr(poc, 'name') else 'unknown poc'}) 因收到关闭信号而中止。")
                    break  # 如果收到关闭信号，则中断对此服务后续 PoC 的验证

                poc_name = getattr(poc, 'name', 'UnknownPoC')
                logger.debug(f"Core._process_open_port: Verifying PoC '{poc_name}' on {ip}:{port_str}")
                results = poc.verify(ip, port_str) # Pass port_str
                logger.debug(f"Core._process_open_port: PoC '{poc_name}' verification result for {ip}:{port_str} -> {'Success' if results else 'Failure'}")
                if results:
                    verified = True  # 标记已通过验证
                    self.data.add_found()  # 发现的漏洞总数加一
                    # 将验证成功的 PoC 结果（通常包括 IP, 端口, 产品, 用户名, 密码, PoC名称等）记录到易受攻击数据中
                    self.data.add_vulnerable(results[:6])

                    # 如果未禁用快照功能，则将快照任务放入处理管道
                    if not self.config.disable_snapshot:
                        # (poc.exploit, results) 元组包含利用漏洞获取快照的方法和验证结果
                        logger.debug(f"Core._process_open_port: Adding snapshot task for PoC '{poc_name}' on {ip}:{port_str}")
                        self.snapshot_pipeline.put((poc.exploit, results))
                # PoC 循环结束

            if not verified:  # 如果遍历完所有 PoC 后，该服务均未验证出漏洞
                logger.debug(f"Core._process_open_port: Product '{product}' on {ip}:{port_str} not verified for any PoC, adding to not_vulnerable.")
                self.data.add_not_vulnerable([ip, port_str, product]) # Use port_str
        else: # 如果指纹识别未能确定产品
            logger.debug(f"Core._process_open_port: {ip}:{port_str} 未识别到产品指纹。") # Kept original Chinese log here
        logger.debug(f"Core._process_open_port: Finished processing for {ip}:{port_str}")

    def _scan(self, target: str):
        logger.debug(f"Core._scan: Starting scan for target: {target}")
        # _scan 方法处理单个目标的扫描逻辑，目标可以是 IP 或 IP:端口 的形式
        items = target.split(':')
        ip = items[0]  # 提取 IP 地址
        # 如果 target 字符串中包含端口号，则使用该端口；否则，使用配置文件中定义的默认端口列表
        # self.config.ports is expected to be a list of strings
        ports_to_scan = [items[1]] if len(items) > 1 else self.config.ports

        # 遍历需要扫描的端口列表
        for port_str in ports_to_scan: # Renamed loop variable to port_str
            if self.shutdown_event.is_set():  # 在处理每个端口前，检查是否已收到关闭信号
                logger.debug(f"Core._scan: Shutdown event set. Aborting further port checks for {ip}.")
                break  # 如果已收到关闭信号，则中断对此目标后续端口的扫描

            logger.debug(f"Core._scan: About to call port_scan for {ip}:{port_str}")
            is_open = port_scan(ip, port_str, self.config.timeout) # Pass port_str
            logger.debug(f"Core._scan: port_scan result for {ip}:{port_str} -> {is_open}")

            if is_open:
                logger.debug(f"Core._scan: Port {ip}:{port_str} is open. Calling _process_open_port.")
                self._process_open_port(ip, port_str) # Call the new helper method
            # else: # 端口未开放或扫描超时/失败，可以选择性记录日志
            #     logger.debug(f"Core._scan: {ip} 端口 {port_str} 关闭或不可达。") # Kept original Chinese log here
        # 端口循环结束
        logger.debug(f"Core._scan: Finished all port checks for target: {target}")

        if self.shutdown_event.is_set(): # 检查在完成对此目标所有指定端口的扫描后，是否是因关闭信号而提前结束的
            logger.info(f"目标 {target} 的扫描因关闭信号而提前结束。") # This is an INFO log, might be okay

        self.data.add_done()  # 标记此目标 (IP) 已完成扫描（无论是否发现漏洞）
        self.data.record_running_state()  # 定期记录当前的运行状态（例如，已完成多少目标）

    def run(self):
        logger.debug("Core.run: Starting Core.run method.") # Added debug log
        logger.info(f"程序运行于 {timer.get_time_formatted()}")
        logger.info(f"当前配置为 {self.config}")

        # 注册信号处理函数，捕获 SIGINT (Ctrl+C) 和 SIGTERM
        # 当捕获到这些信号时，会调用 self._signal_handler 方法
        gevent.signal_handler(signal.SIGINT, self._signal_handler, signal.SIGINT, None)
        gevent.signal_handler(signal.SIGTERM, self._signal_handler, signal.SIGTERM, None) # Handle SIGTERM too

        scan_pool = None # Initialize scan_pool to None
        try:
            # 启动状态栏显示服务
            self.status_bar_service.start()

            # 如果未禁用快照功能，则启动快照处理管道服务
            if not self.config.disable_snapshot:
                self.snapshot_pipeline.start(self) # Pass Core instance here

            # 创建 gevent 协程池，数量由配置中的 th_num (线程数/协程数)决定
            scan_pool = geventPool(self.config.th_num)
            logger.info(f"扫描协程池已启动，并发数: {self.config.th_num}")

            # 遍历 IP 生成器提供的每个 IP 地址进行扫描
            for ip_addr in self.data.ip_generator: # Renamed ip to ip_addr to avoid conflict with module
                logger.debug(f"Core.run: Picked up target '{ip_addr}' from generator.")
                if self.shutdown_event.is_set(): # 检查是否已收到关闭信号
                    logger.info("关闭信号已置位，停止分发新的扫描任务。") # This is an INFO log
                    break  # 如果已收到关闭信号，则停止分发新任务
                # 为每个 IP 启动一个新的 gevent 协程执行 _scan 方法
                scan_pool.start(gevent.spawn(self._scan, ip_addr))

            logger.info("所有扫描任务已分发完毕，等待当前执行中的任务完成...") # This is an INFO log
            if scan_pool: # Check if scan_pool was initialized
                scan_pool.join() # 等待协程池中的所有任务完成
            logger.info("扫描协程池中的所有任务已执行完毕。")

            # 等待状态栏线程结束 (它会根据 core.finish() 和 shutdown_event 自行退出)
            self.status_bar_service.join_thread(timeout=5) # Use a reasonable timeout

            # 如果快照功能已启用，则等待快照处理管道线程结束
            if not self.config.disable_snapshot:
                self.snapshot_pipeline.join_thread(timeout=10) # Use a reasonable timeout

            # 如果程序不是因为关闭信号而结束的，则生成并打印报告
            if not self.shutdown_event.is_set():
                logger.info("开始生成并打印扫描报告...")
                # self.report() # Old call
                report_generator = ReportGenerator(self.config) # New call
                report_generator.generate_console_report()
            else:
                logger.info("程序因收到关闭信号而结束，跳过生成报告。")

        except KeyboardInterrupt:
            # 这个异常块理论上不应该被直接触发，因为 gevent.signal_handler 会先捕获 SIGINT
            # 如果执行到这里，说明可能有地方未正确处理 KeyboardInterrupt 或者信号处理机制出现问题
            logger.warning("Core.run() 中捕获到 KeyboardInterrupt，尝试执行优雅关闭...")
            if not self.shutdown_event.is_set():
                self.shutdown_event.set() # 确保关闭事件被设置
            # 此处可以添加额外的清理逻辑，但主要依赖于 finally 块和各组件的关闭机制
        except Exception as e:
            logger.error(f"Core.run() 中发生未预期错误: {e}", exc_info=True) # 添加 exc_info=True
            if not self.shutdown_event.is_set():
                self.shutdown_event.set() # 出现错误时也尝试优雅关闭
        finally:
            # 确保即使发生异常，也尝试等待后台线程结束
            logger.info("Core.run() 进入 finally 块，执行最终清理...")
            if scan_pool and hasattr(scan_pool, 'join') and not scan_pool.closed: # Ensure pool is not closed before joining
                logger.info("等待扫描协程池中剩余任务完成 (finally)...")
                # scan_pool.join(timeout=10) # Give some time for tasks to finish - This line is redundant due to the next one
                if not scan_pool.join(timeout=10): # Check if it really finished in 10s
                     logger.warning("扫描协程池在10秒超时后未能完成所有任务。")

            # Call join_thread for services in finally block
            self.status_bar_service.join_thread(timeout=5)

            if not self.config.disable_snapshot:
                self.snapshot_pipeline.join_thread(timeout=10)

            logger.info("Core.run() 执行完毕。")