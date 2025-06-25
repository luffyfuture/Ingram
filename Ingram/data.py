"""数据流"""
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty # Ensure Empty is imported
from threading import Lock, RLock, Thread

from loguru import logger

from .utils import common
from .utils import timer
from .utils import net


@common.singleton
class Data:
    # Data 类用于管理扫描任务的数据，包括目标IP、扫描进度、结果记录等。
    # 它采用单例模式，确保在整个应用中只有一个 Data 实例。
    def __init__(self, config):
        # 初始化 Data 实例。
        # config: 全局配置对象。
        self.config = config
        # create_time: 任务创建时的时间戳，用于计算总运行时间。
        self.create_time = timer.get_time_stamp()
        # runned_time: 从状态文件加载的已运行时间 (秒)。
        self.runned_time = 0
        # taskid: 基于输入文件和输出目录生成的唯一任务ID，用于状态文件的命名。
        self.taskid = hashlib.md5((self.config.in_file + self.config.out_dir).encode('utf-8')).hexdigest()

        # total: 待扫描IP总数。
        self.total = 0
        # done: 已完成扫描的IP数量。
        self.done = 0
        # found: 已发现存在漏洞的目标数量 (不是漏洞总数，而是有漏洞的IP数)。
        self.found = 0

        # 为各个计数器和文件操作提供的线程锁，确保多线程环境下的数据一致性。
        self.total_lock = Lock()          # total 计数器锁
        self.found_lock = Lock()          # found 计数器锁
        self.done_lock = Lock()           # done 计数器锁
        self.vulnerable_lock = Lock()     # 易受攻击结果文件写入锁
        self.not_vulneralbe_lock = Lock() # 未发现漏洞文件写入锁 (原文如此，应为 not_vulnerable)

        # 执行预处理操作，如加载状态、计算总数、准备IP生成器。
        self.preprocess()

    def _load_state_from_disk(self):
        # 加载上次运行的状态 (已完成数、发现数、已运行时间) 从磁盘文件。
        # 文件名基于输入文件和输出目录的 MD5 哈希值，确保每个任务有独立的状态文件。
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r', encoding='utf-8') as f: # 指定编码
                    line = f.readline().strip()
                    if line:
                        parts = line.split(',')
                        if len(parts) == 3:
                            self.done = int(parts[0])
                            self.found = int(parts[1])
                            self.runned_time = float(parts[2])
                            logger.info(f"成功从 {state_file} 加载上次运行状态: done={self.done}, found={self.found}, runned_time={self.runned_time:.2f}s。")
                        else:
                            logger.warning(f"状态文件 {state_file} 内容格式不正确 (字段数量: {len(parts)})，将使用默认状态启动。")
                            self.done = 0
                            self.found = 0
                            self.runned_time = 0
                    else:
                        logger.info(f"状态文件 {state_file} 为空，将使用默认状态启动。")
                        self.done = 0
                        self.found = 0
                        self.runned_time = 0
            except (ValueError, IndexError) as e:
                logger.error(f"解析状态文件 {state_file} 时发生错误: {e}。文件可能已损坏。将使用默认状态启动。", exc_info=True)
                self.done = 0
                self.found = 0
                self.runned_time = 0
            except IOError as e:
                logger.error(f"读取状态文件 {state_file} 时发生IO错误: {e}。将使用默认状态启动。", exc_info=True)
                self.done = 0
                self.found = 0
                self.runned_time = 0
        else:
            logger.info(f"未找到状态文件 {state_file}。将作为新任务启动。")
            # 确保在文件不存在时也初始化这些值
            self.done = 0
            self.found = 0
            self.runned_time = 0


    def _cal_total(self):
        # 计算输入文件中目标IP的总数量。
        # 它会读取输入文件 (self.config.in_file)，解析每一行以确定IP段中的IP数量，并累加到 self.total。
        # 支持处理单个IP、IP范围 (如 192.168.1.1-192.168.1.10) 和 CIDR表示法 (如 192.168.1.0/24)。
        # 以 '#' 开头的行被视为注释，将被忽略。
        try:
            with open(self.config.in_file, 'r', encoding='utf-8') as f: # 指定编码
                for line in f:
                    if (strip_line := line.strip()) and not line.startswith('#'):
                        self.add_total(net.get_ip_seg_len(strip_line))
        except FileNotFoundError:
            logger.error(f"输入文件 {self.config.in_file} 未找到，无法计算目标总数。")
        except Exception as e:
            logger.error(f"计算目标总数时发生错误: {e}", exc_info=True)


    def _generate_ip(self):
        # 生成器函数，用于逐个产出待扫描的IP地址。
        # 它会读取输入文件，并根据已完成的扫描数量 (self.done) 来决定从哪里开始生成IP，
        # 从而支持任务的中断和恢复。
        # 如果 self.done > 0，它会跳过已扫描的IP。
        # 对于每个IP段或单个IP，它使用 net.get_all_ip 来获取所有具体的IP地址。
        current_processed_count = 0 # 当前已处理过的IP数量，用于与self.done比较
        ips_to_yield_from_current_segment = []

        try:
            with open(self.config.in_file, 'r', encoding='utf-8') as f: # 指定编码
                # 阶段1: 如果 self.done > 0, 跳过已处理的IP段或部分IP段
                if self.done > 0:
                    for line in f:
                        if (strip_line := line.strip()) and not line.startswith('#'):
                            segment_len = net.get_ip_seg_len(strip_line)
                            if current_processed_count + segment_len <= self.done:
                                current_processed_count += segment_len
                                continue # 跳过整个IP段
                            else:
                                # 定位到 self.done 所在的IP段
                                ips_in_segment = net.get_all_ip(strip_line)
                                # 计算此段内需要跳过的IP数量
                                skip_in_segment = self.done - current_processed_count
                                # 缓存此段中剩余待处理的IP
                                ips_to_yield_from_current_segment = ips_in_segment[skip_in_segment:]
                                break # 找到了开始点，跳出此循环

                    # 产出当前段中剩余的IP
                    for ip_addr in ips_to_yield_from_current_segment: # Renamed ip to ip_addr
                        logger.debug(f"Data._generate_ip: Yielding IP from 'remain' list (segment: '{strip_line}'): {ip_addr}")
                        yield ip_addr
                    # ips_to_yield_from_current_segment 处理完毕后，后续行应从头开始处理
                    # 接下来的循环会继续从 f 中读取下一行

                # 阶段2: 处理文件中的剩余行 (如果done=0，则从头开始)
                for line in f: # 如果done>0且已找到断点，此循环会从断点后的下一行开始
                    if (strip_line := line.strip()) and not line.startswith('#'):
                        for ip_addr in net.get_all_ip(strip_line): # Renamed ip to ip_addr
                            logger.debug(f"Data._generate_ip: Yielding IP from file line '{strip_line}': {ip_addr}")
                            yield ip_addr
        except FileNotFoundError:
            logger.error(f"输入文件 {self.config.in_file} 未找到，无法生成IP列表。")
            # yield from () # 返回一个空生成器
        except Exception as e:
            logger.error(f"生成IP列表时发生错误: {e}", exc_info=True)
            # yield from ()


    def preprocess(self):
        # 执行预处理任务，为正式扫描做准备。
        # 1. 打开用于记录结果的文件 (易受攻击列表和未发现漏洞列表)。
        #    使用追加模式 'a'，以便在任务恢复时可以继续写入。
        try:
            self.vulnerable = open(os.path.join(self.config.out_dir, self.config.vulnerable), 'a', encoding='utf-8')
            self.not_vulneralbe = open(os.path.join(self.config.out_dir, self.config.not_vulnerable), 'a', encoding='utf-8')
        except IOError as e:
            logger.error(f"打开结果文件失败: {e}", exc_info=True)
            # 如果结果文件无法打开，可能需要决定是否中止程序
            raise # 重新抛出异常，让上层处理或终止程序

        # 2. 从磁盘加载上次的运行状态 (如果存在)。
        self._load_state_from_disk()

        # 3. 在单独的线程中计算目标IP总数，避免阻塞主流程。
        #    这对于非常大的输入列表尤其有用。
        cal_thread = Thread(target=self._cal_total)
        cal_thread.start()

        # 4. 初始化IP生成器。
        self.ip_generator = self._generate_ip()

        # 5. 等待计算总数的线程完成，确保 self.total 在扫描开始前是准确的。
        cal_thread.join()
        logger.info(f"预处理完成。目标IP总数: {self.total}。已完成: {self.done}。")


    def add_total(self, item=1):
        # 线程安全地增加待扫描IP的总数。
        # item: 可以是单个数字或包含多个数字的列表。
        with self.total_lock:
            if isinstance(item, int):
                self.total += item
            elif isinstance(item, list):
                self.total += sum(item)

    def add_found(self, item=1):
        # 线程安全地增加已发现存在漏洞的目标数量。
        # item: 可以是单个数字或包含多个数字的列表。
        with self.found_lock:
            if isinstance(item, int):
                self.found += item
            elif isinstance(item, list):
                self.found += sum(item)

    def add_done(self, item=1):
        # 线程安全地增加已完成扫描的IP数量。
        # item: 可以是单个数字或包含多个数字的列表。
        with self.done_lock:
            if isinstance(item, int):
                self.done += item
            elif isinstance(item, list):
                self.done += sum(item)

    def add_vulnerable(self, item: list):
        # 线程安全地将一条易受攻击的记录写入到结果文件。
        # item: 一个列表，包含漏洞信息的各个字段 (例如 [ip, port, product, user, pass, poc_name])。
        try:
            with self.vulnerable_lock:
                self.vulnerable.writelines(','.join(map(str, item)) + '\n') # 确保所有部分都是字符串
                self.vulnerable.flush() # 确保立即写入磁盘
        except IOError as e:
            logger.error(f"写入易受攻击记录到文件失败: {e}", exc_info=True)
        except Exception as e: # 其他潜在错误，如 self.vulnerable 未正确初始化
            logger.error(f"写入易受攻击记录时发生未知错误: {e}", exc_info=True)


    def add_not_vulnerable(self, item: list):
        # 线程安全地将一条未发现漏洞的记录写入到结果文件。
        # item: 一个列表，包含目标信息的各个字段 (例如 [ip, port, product])。
        try:
            with self.not_vulneralbe_lock: # 修正变量名 (应为 not_vulnerable_lock)
                self.not_vulneralbe.writelines(','.join(map(str,item)) + '\n') # 确保所有部分都是字符串
                self.not_vulneralbe.flush() # 确保立即写入磁盘
        except IOError as e:
            logger.error(f"写入未发现漏洞记录到文件失败: {e}", exc_info=True)
        except Exception as e: # 其他潜在错误
            logger.error(f"写入未发现漏洞记录时发生未知错误: {e}", exc_info=True)


    def record_running_state(self):
        # 定期记录当前的运行状态 (已完成数、发现数、累计运行时间) 到状态文件。
        # 当前逻辑是每处理完20个目标记录一次。
        # 这种机制有助于在程序意外中断后恢复扫描进度。
        if self.done > 0 and self.done % 20 == 0: # 确保 self.done 大于0再取模
            try:
                current_elapsed_time = timer.get_time_stamp() - self.create_time
                total_run_time_for_state = self.runned_time + current_elapsed_time
                state_file_path = os.path.join(self.config.out_dir, f".{self.taskid}")
                with open(state_file_path, 'w', encoding='utf-8') as f: # 指定编码
                    f.write(f"{str(self.done)},{str(self.found)},{total_run_time_for_state}")
                logger.debug(f"运行状态已记录到 {state_file_path}。")
            except IOError as e:
                logger.error(f"记录运行状态到文件失败: {e}", exc_info=True)
            except Exception as e:
                logger.error(f"记录运行状态时发生未知错误: {e}", exc_info=True)


    def __del__(self):
        # Data 对象销毁前的清理操作 (Python 的析构方法)。
        # 主要用于确保最终的运行状态被记录，以及所有打开的文件句柄被关闭。
        # 使用 try-except 块以防止在清理过程中抛出异常导致程序退出不优雅。
        try:
            logger.info("正在执行 Data 对象清理操作...")
            self.record_running_state() # 尝试最后记录一次状态
            if hasattr(self, 'vulnerable') and self.vulnerable and not self.vulnerable.closed:
                self.vulnerable.close()
                logger.debug("易受攻击结果文件已关闭。")
            if hasattr(self, 'not_vulneralbe') and self.not_vulneralbe and not self.not_vulneralbe.closed: # 修正变量名
                self.not_vulneralbe.close()
                logger.debug("未发现漏洞结果文件已关闭。")
            logger.info("Data 对象清理操作完成。")
        except Exception as e:
            # 在 __del__ 方法中，应谨慎处理异常，避免因清理失败而引发新的问题。
            # 通常建议只记录错误，不向上抛出。
            logger.error(f"Data 对象清理过程中发生错误: {e}", exc_info=True)


@common.singleton
class SnapshotPipeline:
    def __init__(self, config):
        self.config = config  # 应用配置实例
        self.var_lock = RLock()  # 用于同步访问共享变量 (如 self.done) 的可重入锁
        # 创建一个有界队列用于存放快照任务，队列长度为配置线程数的两倍
        self.pipeline = Queue(self.config.th_num * 2)
        # 创建一个线程池用于执行快照任务，最大工作线程数为配置的 th_num
        self.workers = ThreadPoolExecutor(self.config.th_num)
        # 快照文件存储目录
        self.snapshots_dir = os.path.join(self.config.out_dir, self.config.snapshots)
        # 初始化已完成的快照数量 (通过列出快照目录中的文件数)
        self.done = len(os.listdir(self.snapshots_dir))
        self.task_count = 0  # 当前在队列中或正在处理的快照任务数量
        self.task_count_lock = Lock() # 用于同步访问 task_count 的锁
        self.thread = None # 快照处理线程
        self.core_instance = None # Core 类的实例，用于访问共享事件和状态

    def start(self, core_instance):
        """启动快照处理线程"""
        self.core_instance = core_instance
        if self.thread is None or not self.thread.is_alive():
            self.thread = Thread(target=self.process, args=[core_instance, ], daemon=True)
            self.thread.start()
            logger.info("SnapshotPipeline 线程已启动。")
        else:
            logger.info("SnapshotPipeline 线程已经在运行。")

    def join_thread(self, timeout=None):
        """等待快照处理线程结束"""
        if self.thread and self.thread.is_alive():
            logger.info(f"等待 SnapshotPipeline 线程结束 (超时时间: {timeout}s)...")
            self.thread.join(timeout)
            if self.thread.is_alive():
                logger.warning(f"SnapshotPipeline 线程在超时 ({timeout}s) 后未能结束。")
            else:
                logger.info("SnapshotPipeline 线程已成功结束。")
        else:
            logger.info("SnapshotPipeline 线程未运行或已结束，无需等待。")

    def put(self, msg):
        # 将一条消息 (快照任务) 放入处理管道 (队列)
        # Queue.put() 方法本身是线程安全的，并且在队列满时会阻塞
        # msg 通常是 (poc.exploit_function, results_from_verify) 形式的元组
        self.pipeline.put(msg)

    def empty(self):
        # 检查任务队列是否为空
        return self.pipeline.empty()

    def get(self):
        # 从任务队列中获取一个任务 (此方法在当前代码中未被外部直接调用，process方法内部调用 self.pipeline.get)
        return self.pipeline.get()

    def get_done(self):
        # 获取已完成的快照数量 (线程安全)
        with self.var_lock:
            return self.done

    def add_done(self, num=1):
        # 增加已完成快照的数量 (线程安全)
        with self.var_lock:
            self.done += num

    def _snapshot(self, exploit_func, results):
        # 私有方法，用于执行单个快照任务
        # exploit_func: PoC 的 exploit 方法，用于获取实际的快照数据
        # results: PoC 的 verify 方法成功时的返回结果，通常包含 IP、端口等信息

        # 尝试获取 exploit_func 的名称，如果失败则使用通用名称
        func_name = exploit_func.__name__ if hasattr(exploit_func, '__name__') else 'exploit_func'
        logger.debug(f"开始为 {results[:2]} 执行快照，利用函数: {func_name}")

        # 调用 exploit_func 并传入验证结果
        # res 通常是成功获取的快照数量 (例如 1 表示成功，0 表示失败)
        try:
            if res := exploit_func(results):
                self.add_done(res) # 增加已完成快照的计数
                logger.debug(f"快照任务 {results[:2]} (函数: {func_name}) 成功完成，获取到 {res} 个快照。")
            else:
                logger.debug(f"快照任务 {results[:2]} (函数: {func_name}) 未获取到快照或执行未返回有效结果。")
        except Exception as e:
            logger.error(f"快照任务 {results[:2]} (函数: {func_name}) 执行时发生异常: {e}", exc_info=True)

        # 减少正在处理的任务计数
        with self.task_count_lock:
            self.task_count -= 1

    def process(self, core_instance): # Changed parameter name to core_instance for clarity
        # logger.info("快照处理管道线程已启动。") # Moved to start() method
        # 快照处理主循环
        # 持续运行，直到核心扫描任务完成 (core_instance.finish() 返回 True)
        # 或收到关闭信号 (core_instance.shutdown_event.is_set() 返回 True)
        if self.core_instance is None: # Ensure core_instance is set, typically by start()
            logger.error("SnapshotPipeline.process 调用时 core_instance 未设置!")
            return

        while not self.core_instance.finish() and not self.core_instance.shutdown_event.is_set():
            # 如果已收到关闭信号，并且当前任务队列已空，则可以安全退出循环，不再等待新任务
            if self.pipeline.empty() and self.core_instance.shutdown_event.is_set():
                logger.info("快照管道收到关闭信号且队列已空，准备退出处理循环。")
                break

            try:
                # 从队列中获取快照任务，设置超时时间为1秒
                # 这样做是为了使循环能够响应 shutdown_event，而不是无限期阻塞在 get() 上
                exploit_func, results = self.pipeline.get(timeout=1)

                # 增加正在处理的任务计数 (在任务提交前增加，确保计数准确性)
                with self.task_count_lock:
                    self.task_count += 1

                # 将 _snapshot 方法（及参数）提交到线程池执行
                self.workers.submit(self._snapshot, exploit_func, results)

            except Empty: # queue.Empty 异常 (需要 from queue import Empty)
                # 如果在超时时间内队列为空，则捕获 Empty 异常
                # 再次检查关闭信号，如果已设置且队列仍为空，则退出循环
                if self.core_instance.shutdown_event.is_set() and self.pipeline.empty():
                    logger.info("快照管道在超时等待后，收到关闭信号且队列仍为空，退出处理循环。")
                    break
                continue # 继续下一次循环，尝试获取任务或检查退出条件
            except Exception as e: # 更通用的异常处理
                logger.error(f"快照处理管道在获取或提交任务时发生错误: {e}", exc_info=True)
                # 如果发生未知错误导致任务未能正确计数，这里可能需要错误恢复逻辑
                # 例如，如果在 task_count += 1 之后但在 submit 之前失败，task_count 可能需要调整
                # 不过当前的 submit 是非阻塞的，主要错误可能在 get() 或 task_count_lock 阶段

        logger.info("快照处理循环已结束。等待所有快照工作线程完成...")
        # 关闭线程池，wait=True 表示等待所有已提交的任务执行完毕
        self.workers.shutdown(wait=True)
        logger.info("所有快照工作线程已关闭。快照处理管道线程即将退出。")