# wireguard-oneshot

WireGuardサーバーにアクセスし、UDPパケットを１回送信して応答を受信するプログラムです。
root権限やNET_ADMIN capabilityなくWireGuardを利用できます。
主にSORACOM Arcをターゲットとしています。

# 使い方

バイナリを[リリースページ](https://github.com/1stship/wireguard-oneshot/releases)からダウンロードしてお使いください。

```
wireguard-oneshot
  -privateKey           string WireGuardサーバーの秘密鍵
  -publicKey            string WireGuardサーバーの公開鍵
  -endpoint             string WireGuardサーバーのエンドポイント
  -clientIpAddress      string WireGuardクライアントのIPアドレス
  -destinationIpAddress string 宛先のIPアドレス
  -destinationPort      int    宛先ポート
  -payload              string ペイロード
  -payloadFormat        string ペイロードの形式(text or base64)
```

# ライセンス

[ライセンス](https://github.com/1stship/wireguard-oneshot/blob/main/LICENSE)をご覧ください。

# 謝辞

"WireGuard "および "WireGuard "ロゴは、Jason A. Donenfeldの登録商標です。
ソースコードは、WireGuard LLCが[ライセンス](https://git.zx2c4.com/wireguard-go/tree/LICENSE)の条件で著作権を有する[wireguard-go](https://git.zx2c4.com/wireguard-go/)の派生物です。