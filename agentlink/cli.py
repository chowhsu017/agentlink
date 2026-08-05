"""AgentLink CLI — 命令行工具"""
import argparse, sys, os, asyncio, json, time


def cmd_serve(args):
    """启动完整 AgentLink 服务（信令 + 频道 + Presence）"""
    try:
        from agentlink.signal import SignalServer, create_signal_app
        from agentlink.p2 import add_channel_relay, add_presence_federation
    except ImportError as e:
        print(f"缺少依赖: {e}")
        print("安装: pip install agentlink[full]")
        sys.exit(1)

    import uvicorn

    # 默认路径：~/.agentlink/
    home = os.path.expanduser("~/.agentlink")
    os.makedirs(home, exist_ok=True)
    signal = SignalServer(
        db_path=args.db or os.path.join(home, "signal.db"),
        key_path=args.key or os.path.join(home, "signal_key.json"),
    )
    app = create_signal_app(signal)

    # 挂载 P2 能力：频道中继 + Presence 联邦
    from agentlink.p2 import ChannelRelay
    channel_relay = ChannelRelay(
        db_path=args.channel_db or os.path.join(home, "channels.db"),
        signal_server=signal,
    )
    add_channel_relay(app, channel_relay)
    add_presence_federation(app, signal)

    host = args.host or "127.0.0.1"
    port = args.port or 9765

    print(f"\n🚀 AgentLink 服务启动 @ {host}:{port}")
    print(f"   DID:      {signal.kp.did}")
    print(f"   密钥:     {signal.key_path}")
    print(f"   DB:       {signal.db_path}")
    print(f"   频道 DB:  {channel_relay.db_path}")
    print(f"")
    print(f"   📡 信令:     ws://{host}:{port}/signal/ws")
    print(f"   📢 频道:     http://{host}:{port}/channel/create")
    print(f"   👥 Presence:  http://{host}:{port}/signal/status")
    print(f"   🔑 管理:     agentlink keygen <name>")
    print(f"")
    print(f"   客户端接入: SignalClient(signal_url='http://{host}:{port}')")

    uvicorn.run(app, host=host, port=port, log_level=args.log_level or "warning")


def cmd_keygen(args):
    """生成密钥对"""
    from agentlink import generate_keypair, save_keypair

    kp = generate_keypair(args.name)
    path = args.output or f"agentlink_{args.name}.key.json"
    save_keypair(kp, path)
    print(f"🔑 密钥对已生成:")
    print(f"  DID:  {kp.did}")
    print(f"  路径: {path}")
    print(f"  身份: Ed25519 公钥 ({len(kp.sign_public)} bytes)")
    print(f"  加密: X25519 公钥 ({len(kp.enc_public)} bytes)")


def cmd_encrypt(args):
    """加密消息"""
    from agentlink import load_keypair, compute_shared_secret, derive_session_key, encrypt_message

    local = load_keypair(args.local_key)
    peer = load_keypair(args.peer_key)
    shared = compute_shared_secret(local.enc_private, peer.enc_public)
    sk, salt = derive_session_key(shared)

    if args.message:
        plaintext = args.message.encode("utf-8")
    elif not sys.stdin.isatty():
        plaintext = sys.stdin.buffer.read()
    else:
        print("请输入要加密的内容 (Ctrl+D 结束):")
        plaintext = sys.stdin.buffer.read()

    enc = encrypt_message(sk, plaintext)
    print(_b64(enc))


def cmd_decrypt(args):
    """解密消息"""
    from agentlink import load_keypair, compute_shared_secret, derive_session_key, decrypt_message
    from agentlink.crypto import _unb64

    local = load_keypair(args.local_key)
    peer = load_keypair(args.peer_key)
    shared = compute_shared_secret(local.enc_private, peer.enc_public)
    sk, salt = derive_session_key(shared)

    if args.b64:
        enc = _unb64(args.b64)
    elif not sys.stdin.isatty():
        enc = _unb64(sys.stdin.read().strip())
    else:
        print("请输入 Base64 密文:")
        enc = _unb64(sys.stdin.read().strip())

    plain = decrypt_message(sk, enc)
    if plain:
        print(plain.decode("utf-8"))
    else:
        print("❌ 解密失败 (密钥不匹配或消息被篡改)")
        sys.exit(1)


def cmd_signal(args):
    """启动信令服务（仅信令，不含频道/Presence）"""
    import uvicorn
    from agentlink.signal import SignalServer, create_signal_app

    home = os.path.expanduser("~/.agentlink")
    os.makedirs(home, exist_ok=True)
    signal = SignalServer(
        db_path=args.db or os.path.join(home, "signal.db"),
        key_path=args.key or os.path.join(home, "signal_key.json"),
    )
    app = create_signal_app(signal)

    host = args.host or "127.0.0.1"
    port = args.port or 9765
    print(f"\n📡 AgentLink 信令服务 @ {host}:{port}")
    print(f"   DID:       {signal.kp.did}")
    print(f"   REST:      http://{host}:{port}/signal/status")
    print(f"   WebSocket: ws://{host}:{port}/signal/ws")
    uvicorn.run(app, host=host, port=port, log_level="warning")


def cmd_channel(args):
    """频道管理"""
    from agentlink import ChannelRelay

    relay = ChannelRelay(db_path=args.db or "agentlink_channels.db")

    if args.action == "create":
        result = relay.create_channel(args.channel_id, args.name, args.creator, e2ee=args.e2ee)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.action == "list":
        channels = relay.list_channels()
        if not channels:
            print("📭 暂无频道")
            return
        for ch in channels:
            icon = "🔒" if ch.get("e2ee") else "📢"
            print(f"  {icon} {ch['name']} ({ch['id']}) — {ch.get('member_count', 0)} 会员")

    elif args.action == "info":
        info = relay.get_channel(args.channel_id)
        if not info:
            print(f"❌ 频道 {args.channel_id} 不存在")
            sys.exit(1)
        members = relay.get_members(args.channel_id)
        info["members"] = members
        print(json.dumps(info, ensure_ascii=False, indent=2, default=str))

    elif args.action == "delete":
        relay.delete_channel(args.channel_id)
        print(f"🗑️ 频道 {args.channel_id} 已删除")

    elif args.action == "history":
        history = relay.get_history(args.channel_id, limit=args.limit or 20)
        if not history:
            print("📭 暂无消息")
            return
        for m in reversed(history):
            ts = time.strftime("%H:%M:%S", time.localtime(m["ts"]))
            sender = m["sender_did"][:20]
            icon = "🔒" if m.get("encrypted") else "📨"
            print(f"  {icon} [{ts}] {sender}: {m['payload'][:80]}")


def main():
    parser = argparse.ArgumentParser(
        prog="agentlink",
        description="AgentLink — Agent-to-Agent 实时通信协议工具",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # serve
    p_serve = sub.add_parser("serve", help="启动完整 AgentLink 服务（信令+频道+Presence）")
    p_serve.add_argument("--port", type=int, default=9765, help="端口 (默认 9765)")
    p_serve.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    p_serve.add_argument("--db", help="信号数据库路径 (默认 ~/.agentlink/signal.db)")
    p_serve.add_argument("--key", help="服务密钥路径 (默认 ~/.agentlink/signal_key.json)")
    p_serve.add_argument("--channel-db", help="频道数据库路径 (默认 ~/.agentlink/channels.db)")
    p_serve.add_argument("--log-level", default="warning", help="日志级别 (默认 warning)")
    p_serve.set_defaults(func=cmd_serve)

    # signal (仅信令服务，轻量模式)
    p_signal = sub.add_parser("signal", help="启动信令服务（仅信令，不含频道/Presence）")
    p_signal.add_argument("--port", type=int, default=9765, help="端口 (默认 9765)")
    p_signal.add_argument("--host", default="127.0.0.1", help="监听地址")
    p_signal.add_argument("--db", help="数据库路径")
    p_signal.add_argument("--key", help="密钥路径")
    p_signal.set_defaults(func=cmd_signal)

    # keygen
    p_key = sub.add_parser("keygen", help="生成密钥对")
    p_key.add_argument("name", help="Agent 名称")
    p_key.add_argument("-o", "--output", help="输出路径 (默认 agentlink_<name>.key.json)")
    p_key.set_defaults(func=cmd_keygen)

    # encrypt
    p_enc = sub.add_parser("encrypt", help="加密消息")
    p_enc.add_argument("local_key", help="发送方密钥文件")
    p_enc.add_argument("peer_key", help="接收方密钥文件")
    p_enc.add_argument("-m", "--message", help="要加密的消息 (省略则从 stdin 读取)")
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser("decrypt", help="解密消息")
    p_dec.add_argument("local_key", help="接收方密钥文件")
    p_dec.add_argument("peer_key", help="发送方密钥文件")
    p_dec.add_argument("-b", "--b64", help="Base64 密文 (省略则从 stdin 读取)")
    p_dec.set_defaults(func=cmd_decrypt)

    # channel
    p_ch = sub.add_parser("channel", help="频道管理")
    p_ch.add_argument("action", choices=["create", "list", "info", "delete", "history"],
                      help="操作")
    p_ch.add_argument("channel_id", nargs="?", help="频道 ID")
    p_ch.add_argument("--name", help="频道名称 (create)")
    p_ch.add_argument("--creator", help="创建者 DID (create)")
    p_ch.add_argument("--e2ee", action="store_true", help="启用 E2EE (create)")
    p_ch.add_argument("--limit", type=int, default=20, help="历史消息条数 (history)")
    p_ch.add_argument("--db", help="数据库路径")
    p_ch.set_defaults(func=cmd_channel)

    # help
    sub.add_parser("help").set_defaults(func=lambda _: parser.print_help())

    args = parser.parse_args()

    # 先注入 _b64 给 encrypt/decrypt 使用
    if args.command in ("encrypt",):
        from agentlink.crypto import _b64 as _b64  # noqa

    args.func(args)


if __name__ == "__main__":
    main()
