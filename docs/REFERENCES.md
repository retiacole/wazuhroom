# 参考資料 / References

Wazuhroom v0.1.1は、Wazuh 4.14系の画面・用語・データ構造を参考にしています。資料の確認日は2026年10月28日です。`current` / `latest` の参照先は将来更新されるため、この教材の実装範囲と同一とは限りません。

Wazuhroom v0.1.1 references Wazuh 4.14 UI concepts, terminology, and event structures. Sources were reviewed on October 28, 2026. Links containing `current` or `latest` may change; they do not define the simulator's supported scope.

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

## 再現範囲と検証 / Fidelity and validation

この教材は独自のHTML/CSS/JavaScriptで実装した学習シミュレーターです。公式UIのソースコードやロゴ、Wazuh Manager・Indexer・Agentは同梱していません。画面構成や用語は上記の公式資料を参考にしています。

検索とフィルターは、同梱した合成イベントを対象に計算します。実機の全検索構文、全文検索の解析器、任意のデータ型、検知ルールの評価は再現していません。ルールIDとアラートレベルは教材用の設定です。実際の標準ルールの検知結果として扱わないでください。

`agent`、`rule`、`decoder`、`data`、`syscheck`、`full_log`等の名前と形を実機の学習に使います。各ケースでは必要な項目を抜粋しており、全フィールドを含む実機の完全な出力ではありません。教材のイベントIDは参照・採点用の安定した識別子です。

`data.srcport` や `data.win.eventdata.logonType` は本教材では数値型です。実機のイベント出力で文字列となる場合との違いを検索ヘルプに明示しています。本教材の数値検索では引用符を使わず、実環境ではイベントの出力形式とインデックスのマッピングを確認します。v0.1.1では既存の数値検索・保存形式を維持しています。

アラート件数は攻撃件数と同じではありません。低レベルのイベントも調査の手掛かりになり、情報が見つからないことだけでは安全とも侵害とも判断できません。接続状態、収集対象、対象期間を資料と合わせて確認します。

自動テストは教材の整合性、検索・採点・保存の実装動作を確認します。テスト合格は、実際のWazuhとの全操作の一致や、実環境に対する検知能力を保証しません。初版では実機との完全な差分検証は実施していません。

This application is a teaching simulator implemented in original HTML/CSS/JavaScript. It does not bundle official UI source code, the official logo, Wazuh Manager, Indexer, or Agent. Its layout and terminology reference the official documentation listed above.

Queries and filters operate on bundled synthetic events. The course does not reproduce every query feature, full-text analyzer, arbitrary field type, or detection-rule evaluation. Rule IDs and alert levels are teaching settings, not measured results from the default ruleset.

Names and structures such as `agent`, `rule`, `decoder`, `data`, `syscheck`, and `full_log` help learners recognize fields in a real deployment. Cases include selected fields rather than a complete real-world export. Event IDs are stable teaching references used for evidence selection and assessment.

`data.srcport` and `data.win.eventdata.logonType` are modeled as numbers in this simulator. Search help explains the difference from real event payloads that may represent them as strings. Use unquoted numbers here; in a real deployment, check both the event format and index mapping. Version 0.1.1 retains the existing numeric query behavior and save format.

An alert count is not an attack count. Lower-level events can provide useful context, and an absence of matching records alone proves neither safety nor compromise. Cross-check agent status, collection coverage, and the selected time range.

Automated tests check the content and implementation of search, assessment, and saves. Passing tests does not establish complete behavioral equivalence with Wazuh or production detection performance. A complete differential validation against a live Wazuh deployment has not been performed for this first release.

## 教材設計 / Teaching design

[SOCroom](https://github.com/retiacole/socroom)の調査・判断・報告という教育設計を参考にしています。Wazuhroomでは、Wazuhを使う基本操作と業務フローに範囲を絞り、独立した問題、進捗、画面を持ちます。

Wazuhroom draws on SOCroom's investigation–decision–report approach, with its own cases, progress, and interface focused on basic Wazuh operations and the SOC workflow.

自己学習のため、解答の手掛かりを含むヒントと、提出後の報告例を利用できます。報告例は合否にかかわらず開け、閲覧による減点はありません。証拠欄の数は選択数と上限を示し、上限まで埋める課題ではありません。判断基準の資料は調査を助けるために用意し、閲覧対象を増やすことで既存の完了記録を無効にする設計にはしていません。

For self-study, learners can use hints containing solution clues and open an example report after a submission, whether it passes or fails. Viewing these aids carries no penalty. The evidence counter shows the selection and its upper limit; filling that allowance is not the task. Triage-policy references support investigation without introducing additional required document views that would invalidate existing completion records.

roomシリーズ全体の紹介では、hanabi-simulatorと同じ「その他のプロジェクト / Other projects」に分類します。メイン教材の学習順や卒業条件には追加しません。

In the room-series profile, this project belongs to **Other projects**, alongside hanabi-simulator. It does not add a prerequisite or graduation requirement to the main learning path.

## 名称とライセンス / Name and license

WazuhはWazuh Inc.の商標です。本教材はWazuh Inc.とは提携しておらず、同社による提供・認定・承認・支援を示すものではありません。このプロジェクトの独自実装に適用するMITライセンスは、Wazuhの名称・商標・ブランド素材についての利用許諾を与えません。名称や画面の利用について、許可取得済み・権利確認完了と表明するものではありません。

Wazuh is a trademark of Wazuh Inc. This project is not affiliated with Wazuh Inc. and is not provided, certified, approved, or endorsed by the company. The MIT License covering this project's original implementation does not grant permission to use Wazuh's name, trademarks, or branding materials. This notice does not assert that permission has been obtained or that use of the name or interface has received legal clearance.
