# 参考資料 / References

Wazuhroom v0.2.0は、Wazuh 4.14系の画面・用語・データ構造を参考にしています。資料の確認日は2026年10月28日です。`current` / `latest` の参照先は将来更新されるため、この教材の実装範囲と同一とは限りません。

Wazuhroom v0.2.0 references Wazuh 4.14 UI concepts, terminology, and event structures. Sources were reviewed on October 28, 2026. Links containing `current` or `latest` may change; they do not define the simulator's supported scope.

## 一次資料 / Primary sources

| Reference | 教材で参考にした点 / Use in this course |
| --- | --- |
| [Wazuh: Navigating the dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.html) | エージェント管理、Threat Hunting、File Integrity Monitoringの構成 / Agent management, Threat Hunting, and FIM navigation |
| [OpenSearch: Discover](https://docs.opensearch.org/latest/dashboards/getting-started/explore-discover/) | 期間、条件、一覧、詳細を使った調査 / Investigating with time ranges, filters, results, and details |
| [OpenSearch: DQL](https://docs.opensearch.org/latest/dashboards/dql/) | イベント検索構文とフィールド型 / Event query syntax and field types |
| [Wazuh: Dashboard WQL](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/queries.html) | エージェント等の管理データ検索。DQLとの区別 / Management-data queries, distinct from event DQL |
| [Microsoft: Security event 4733](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4733) | ローカルグループからのメンバー削除と、グループ自体の削除の区別 / Removing a member from a local group, distinct from deleting the group |
| [Wazuh: Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) | カスタムルールIDの範囲 / Custom-rule ID range |
| [Wazuh: Custom FIM rules](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html) | `syscheck`、`agent`、`rule`、`decoder`、`full_log`などのイベント構造 / FIM alert structure |
| [Wazuh: Alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html) | アラートと収集されたイベントの区別 / Distinguishing alerts from collected events |
| [Wazuh: Agent life cycle](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/agent-life-cycle.html) | 接続状態の読み方 / Understanding agent status |
| [Wazuh: Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html) | 本教材の調査・報告と、実際の自動対処の区別 / Distinguishing investigation/reporting from real automated responses |
| [Wazuh: Trademark and Brand Policy](https://wazuh.com/docs/legal-resources/Trademark_and_Brand_Policy_May_2024.pdf) | 名称・商標・ブランド素材の扱い。ソフトウェアのライセンスとは別 / Name, trademark, and branding terms, separate from the software license |
| [RFC 5737: IPv4 Address Blocks Reserved for Documentation](https://www.rfc-editor.org/rfc/rfc5737.html) | 合成シナリオの外部IPv4アドレスに使う文書用アドレス範囲 / Documentation address ranges for external IPv4 addresses in synthetic scenarios |
| [RFC 2606: Reserved Top Level DNS Names](https://www.rfc-editor.org/rfc/rfc2606.html) | 合成シナリオの通信先に使う例示用ドメイン / Reserved example domain names for synthetic destinations |

## 再現範囲と検証 / Fidelity and validation

この教材は独自のHTML/CSS/JavaScriptで実装した学習シミュレーターです。公式UIのソースコードやロゴ、Wazuh Manager・Indexer・Agentは同梱していません。画面構成や用語は上記の公式資料を参考にしています。

検索とフィルターは、同梱した合成イベントを対象に計算します。実機の全検索構文、全文検索の解析器、任意のデータ型、検知ルールの評価は再現していません。ルールIDとアラートレベルは教材用の設定です。実際の標準ルールの検知結果として扱わないでください。

`agent`、`rule`、`decoder`、`data`、`syscheck`、`full_log`等の名前と形を実機の学習に使います。各ケースでは必要な項目を抜粋しており、全フィールドを含む実機の完全な出力ではありません。教材のイベントIDは参照・採点用の安定した識別子です。

`data.srcport` や `data.win.eventdata.logonType` は本教材では数値型です。実機のイベント出力で文字列となる場合との違いを検索ヘルプに明示しています。本教材の数値検索では引用符を使わず、実環境ではイベントの出力形式とインデックスのマッピングを確認します。既存フィールドの数値検索の動作は維持しています。

追加ケースの `data.process.*`、`data.http.*`、`data.artifact.*`、`data.schedule` は、合成した観測を検索するための教材独自の項目です。PID・PPID・CPU値・HTTP状態コードは数値型、プロセス引数とHTTP本文・応答の要約はtext型としています。実際のWazuhデコーダーやインデックスが同じ項目・型を出力することを保証しません。

アラート件数は攻撃件数と同じではありません。低レベルのイベントも調査の手掛かりになり、情報が見つからないことだけでは安全とも侵害とも判断できません。接続状態、収集対象、対象期間を資料と合わせて確認します。

自動テストは教材の整合性、検索・採点・保存の実装動作を確認します。テスト合格は、実際のWazuhとの全操作の一致や、実環境に対する検知能力を保証しません。初版では実機との完全な差分検証は実施していません。

This application is a teaching simulator implemented in original HTML/CSS/JavaScript. It does not bundle official UI source code, the official logo, Wazuh Manager, Indexer, or Agent. Its layout and terminology reference the official documentation listed above.

Queries and filters operate on bundled synthetic events. The course does not reproduce every query feature, full-text analyzer, arbitrary field type, or detection-rule evaluation. Rule IDs and alert levels are teaching settings, not measured results from the default ruleset.

Names and structures such as `agent`, `rule`, `decoder`, `data`, `syscheck`, and `full_log` help learners recognize fields in a real deployment. Cases include selected fields rather than a complete real-world export. Event IDs are stable teaching references used for evidence selection and assessment.

`data.srcport` and `data.win.eventdata.logonType` are modeled as numbers in this simulator. Search help explains the difference from real event payloads that may represent them as strings. Use unquoted numbers here; in a real deployment, check both the event format and index mapping. Existing numeric query behavior is retained.

The added case uses custom teaching fields under `data.process.*`, `data.http.*`, and `data.artifact.*`, plus `data.schedule`, to search its synthetic observations. PIDs, PPIDs, CPU values, and HTTP status codes are numbers; process arguments and HTTP body/response summaries are text fields. This does not guarantee matching fields or types from a real Wazuh decoder or index.

An alert count is not an attack count. Lower-level events can provide useful context, and an absence of matching records alone proves neither safety nor compromise. Cross-check agent status, collection coverage, and the selected time range.

Automated tests check the content and implementation of search, assessment, and saves. Passing tests does not establish complete behavioral equivalence with Wazuh or production detection performance. A complete differential validation against a live Wazuh deployment has not been performed for this first release.

## 合成データと匿名化 / Synthetic data and anonymization

v0.2.0の追加調査は、Webサービスの実行アカウントによる不審プロセス、外部接続、繰り返す実行という行動パターンを使った独自の合成シナリオです。実在の記録を一対一で再現したり、識別子だけを置換して公開したりするものではありません。HTTPの応答コードやファイル転送だけでプログラムの実行成功を断定せず、ホスト上の観測と区別します。定期実行設定の存在と実際の起動原因も分けて扱います。

追加演習の改訂2では、WebshellへのPOST要求とサーバー上のファイル確認を別々の観測として扱います。URLの公開先設定と読取り専用レビューを資料に明示し、要求URIだけから実パスを求めないようにしています。Base64はWebshellに送られたPOST本文の教材データであり、Webshellファイル内部から取得したものとはしていません。

復号対象は、新しく作成した非実行の疑似コードです。エラー表示の抑制、アプリケーション側の要求変数の変更、メール送信要求と戻り値の表示という意図を読みます。実際のPHPコード、元のBase64、メール宛先・個人情報は転載しません。`REMOTE_ADDR` の代入は実際の通信元を変える証拠ではなく、`SCRIPT_NAME` の代入もファイルの所在を示しません。メール送信を要求する内容や関数の戻り値から、受信者への配達成功は断定しません。復号器はブラウザ内でテキストを表示するだけで、内容を実行しません。

イベント、時刻、プロセスID、通信先、パス、アカウント、管理者の対処メモ、承認・収集範囲の資料は、演習内で整合するよう作成しています。これらの補完資料と監視ログは教材上の仮定であり、原観測から得た追加の事実ではありません。実際のPCAPから生成したWazuhの出力や、実機で検証した検知結果でもありません。初期侵入経路、root権限、操作主体の同一性、再実行の仕組み、完全な駆除は、用意した観測だけで確定させない設計です。

公開物には元資料、PCAP、画像、元のコマンドやペイロード、実値と架空値の対応表を含めません。識別情報の点検はIP・URL・パスに限定せず、人名・組織名、ホスト名、アカウント、日時、メールアドレス、ハッシュ、ウォレット、MACアドレス、UUID、資格情報、HTTPヘッダー・Cookie、符号化データやメタデータも対象とします。学習に不要な項目は削除し、必要な項目は独自の架空値として構成します。技術一般名、プロトコル、標準フィールド名は理解に必要なため維持します。この方針は、実在記録の完全な匿名化を保証するものではありません。

外部IPv4アドレスには[RFC 5737の文書用アドレス範囲](https://www.rfc-editor.org/rfc/rfc5737.html)、通信先のドメインには[RFC 2606の例示用ドメイン](https://www.rfc-editor.org/rfc/rfc2606.html)を使います。表示される通信やコマンドは教材データであり、実際の接続や実行は行いません。

The investigation added in v0.2.0 is an original synthetic scenario using behavior patterns such as suspicious processes under a web-service account, outbound connections, and recurring execution. It does not reproduce real records one for one or publish them with identifiers substituted. HTTP response codes and file transfers alone do not establish successful program execution; host observations are considered separately. The presence of a scheduled task is also distinguished from proof of what launched a process.

Revision 2 treats POST requests to a web shell and server-side file review as separate observations. A documented web-publication mapping and read-only review establish the file location; the request URI alone does not. The teaching Base64 appears in a POST body sent to the web shell. It is not presented as content extracted from inside the web-shell file.

The decoded sample is newly authored, non-executable pseudocode. Learners interpret requested error-display suppression, changes to application request variables, a mail-delivery request, and display of the request result. Original PHP code, Base64, email recipients, and personal content are excluded. Assigning `REMOTE_ADDR` does not prove a change to the real network source; assigning `SCRIPT_NAME` does not establish a file's location. A mail request or function return value does not establish delivery to a recipient. The decoder displays text within the browser and never executes its contents.

Events, times, process IDs, destinations, paths, accounts, administrator response notes, approvals, and collection-coverage documents are authored to form a coherent exercise. These supporting documents and monitoring records are teaching assumptions, not additional facts recovered from original observations. They are neither Wazuh output generated from an actual PCAP nor detections verified on a live deployment. The available evidence is not designed to establish the initial entry route, root privileges, a shared actor, the mechanism of recurring execution, or complete eradication.

Published artifacts exclude source documents, PCAPs, images, original commands or payloads, and mappings between real and fictional values. Identifier review covers more than IP addresses, URLs, and paths: it includes personal and organization names, hostnames, accounts, timestamps, email addresses, hashes, wallets, MAC addresses, UUIDs, credentials, HTTP headers and cookies, encoded data, and metadata. Unnecessary items are omitted; necessary values are independently fictionalized. General technology names, protocols, and standard field names are retained for learning. This policy does not claim complete anonymization of real records.

External IPv4 values use the [documentation ranges in RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html); destination domains use [reserved examples in RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html). Displayed traffic and commands are teaching data; the application does not connect to those destinations or execute commands.

## 教材設計 / Teaching design

[SOCroom](https://github.com/retiacole/socroom)の調査・判断・報告という教育設計を参考にしています。Wazuhroomでは、Wazuhを使う基本操作と業務フローに範囲を絞り、独立した問題、進捗、画面を持ちます。

Wazuhroom draws on SOCroom's investigation–decision–report approach, with its own cases, progress, and interface focused on basic Wazuh operations and the SOC workflow.

自己学習のため、解答の手掛かりを含むヒントと、提出後の報告例を利用できます。報告例は合否にかかわらず開け、閲覧による減点はありません。証拠欄の数は選択数と上限を示し、上限まで埋める課題ではありません。判断基準の資料は調査を助けるための任意資料です。追加演習の改訂2では新設問・証拠・必須資料が増えるため、その演習だけ完了条件を再確認します。以前の提出は参考記録として残し、最初の7演習の完了記録は維持します。

For self-study, learners can use hints containing solution clues and open an example report after a submission, whether it passes or fails. Viewing these aids carries no penalty. The evidence counter shows the selection and its upper limit; filling that allowance is not the task. The triage policy remains optional reading guidance. Revision 2 adds questions, evidence, and required material to the web-server case, so that case's completion must be checked again. Its earlier submission remains a reference record; completion of the first seven cases is preserved.

roomシリーズ全体の紹介では、hanabi-simulatorと同じ「その他のプロジェクト / Other projects」に分類します。メイン教材の学習順や卒業条件には追加しません。

In the room-series profile, this project belongs to **Other projects**, alongside hanabi-simulator. It does not add a prerequisite or graduation requirement to the main learning path.

## 名称とライセンス / Name and license

WazuhはWazuh Inc.の商標です。本教材はWazuh Inc.とは提携しておらず、同社による提供・認定・承認・支援を示すものではありません。このプロジェクトの独自実装に適用するMITライセンスは、Wazuhの名称・商標・ブランド素材についての利用許諾を与えません。名称や画面の利用について、許可取得済み・権利確認完了と表明するものではありません。

Wazuh is a trademark of Wazuh Inc. This project is not affiliated with Wazuh Inc. and is not provided, certified, approved, or endorsed by the company. The MIT License covering this project's original implementation does not grant permission to use Wazuh's name, trademarks, or branding materials. This notice does not assert that permission has been obtained or that use of the name or interface has received legal clearance.
