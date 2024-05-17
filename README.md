こちら( https://github.com/StrikerX3/whvpclient )のコードを参考に、`whvp.cpp`ファイルを変更しそれぞれ以下のような機能を試しました。

* `MMIOPrint`: MMIOの機能を使って、12行目で定義した`disp_str`をメモリに書き込んでいます
* `executeSimpleBinary`: 16進数で2桁空白区切り表記したx86_64バイナリテキストファイルを読み込み、実行します。再帰関数やprint機能、forやwhileには対応していません。
* `hypercallPrint`: `printf "文字列"`という入力をするとホスト側からHypercallを受け取ってゲストがprintをする機能、そして`exec "filw path"`とすると`eecuteSimpleBinary`の機能を実行します
* * `writetoVirtualMemoryAndPrint`: 入力した文字列をカーネル設定の段階でメモリに書き込み、それを読み出します。
