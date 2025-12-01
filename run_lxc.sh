#!/bin/bash
# run_lxc.sh  ——  最终稳定版（兼容所有 perf 版本 + 支持 Ctrl+C 安全退出）

CONTAINER="encrypt"
SNAPSHOT="snap1"
CGROUP="/lxc.payload.encrypt"
OUTPUT_DIR="./hpc_results"

mkdir -p "$OUTPUT_DIR"

# =============== Ctrl+C 安全退出处理 ===============
trap_ctrlc() {
    echo -e "\n\n[$(date +%T)] 检测到 Ctrl+C，正在安全终止所有实验..."
    echo "正在杀掉残留的 perf、容器、程序进程..."
    
    sudo pkill -9 perf 2>/dev/null || true
    sudo lxc-stop -n "$CONTAINER" -k 2>/dev/null || true
    sudo kill $LXC_PID 2>/dev/null || true
    sudo kill $PERF_PID 2>/dev/null || true
    sudo kill $PROG_PID 2>/dev/null || true
    
    echo "已安全退出。已完成的文件保留在 $OUTPUT_DIR 中。"
    exit 130
}

trap trap_ctrlc SIGINT

# =============== 单次采集函数 ===============
run_experiment() {
    local prog_name="$1"      # benign 或 ransomware
    local run_number="$2"
    local padded=$(printf "%02d" $run_number)
    local output_file="$OUTPUT_DIR/${prog_name}_${padded}.csv"

    echo "============================================"
    echo "开始 $prog_name 第 $run_number 次（第 $(( $(ls $OUTPUT_DIR/${prog_name}_*.csv 2>/dev/null | wc -l) + 1 )) 次实际执行）"
    echo "输出文件: $output_file"
    echo "============================================"

    # 1. 恢复快照
    sudo lxc-snapshot -n "$CONTAINER" -r "$SNAPSHOT"
    sleep 5

    # 2. 启动容器（前台）
    sudo lxc-start -n "$CONTAINER" -F &
    LXC_PID=$!
    sleep 5

    # 3. 先启动 perf：用 timeout 命令精确控制 10.15 秒总时长（兼容所有版本！）
    sudo timeout 10.15 perf stat -x ',' -I 10 \
        -e instructions,cache-references,cache-misses,branches,branch-misses \
        --cgroup="$CGROUP" -a \
        > "$output_file" 2>&1 &
    PERF_PID=$!

    # 4. 等待 perf 完全启动
    sleep 0.1

    # 5. 启动目标程序
    sudo lxc-attach -n "$CONTAINER" -- sudo -i "/home/$prog_name" &
    PROG_PID=$!

    # 6. 程序运行 10 秒
    sleep 10

    # 7. 强制停止所有进程
    sudo lxc-attach -n "$CONTAINER" -- pkill -9 -u user 2>/dev/null || true
    sudo lxc-attach -n "$CONTAINER" -- killall -9 -u user 2>/dev/null || true
    sleep 0.3
    sudo lxc-stop -n "$CONTAINER" -k 2>/dev/null || true
    wait $LXC_PID 2>/dev/null || true

    # 确保 perf 被 timeout 自然结束，或强制杀掉
    sudo kill $PERF_PID 2>/dev/null || true
    wait $PERF_PID 2>/dev/null || true

    echo "✓ $prog_name 第 $run_number 次完成！"
    echo "  结果已保存: $output_file"
    echo
}

# =============== 主循环 ===============
echo "开始实验"
echo

for i in {1..5}; do
    run_experiment "benign" "$i"
done

for i in {1..5}; do
    run_experiment "ransomware" "$i"
done

echo "======================================================================"
echo "完成"
echo "结果目录: $OUTPUT_DIR"
echo "文件列表:"
ls -1 "$OUTPUT_DIR"/*.csv | sort
echo "======================================================================"
