# Wazuhroom v0.1.1

[すぐにやってみる / Play Now](https://retiacole.github.io/wazuhroom/) · [オフライン用HTML / Offline HTML](https://github.com/retiacole/wazuhroom/blob/main/wazuhroom.html)

**WazuhをつかったSOC業務の基本フローと操作方法を体験するコンテンツ。**<br>
**Experience the basic SOC workflow and operations using Wazuh.**

日本語・English / ブラウザのみ / オフライン対応 / インストール・アカウント不要

Wazuhの画面構成を参考に、アラートの確認、期間と条件による絞り込み、イベント詳細と原文の確認、資料との照合、判断・報告を一続きで練習する学習シミュレーターです。学習者がWazuhを起動したり、監視対象端末を準備したりする必要はありません。

roomシリーズの独立した追加教材です。メインのおすすめ学習順には含めず、興味や必要に応じて選べます。他のroomの履修や進捗の引継ぎは不要です。

## はじめ方

1. [Play Now](https://retiacole.github.io/wazuhroom/)を開きます。オフラインでは、[wazuhroom.html](https://github.com/retiacole/wazuhroom/blob/main/wazuhroom.html)の **Download raw file** で保存したHTMLをブラウザで開きます。リポジトリ全体を **Code → Download ZIP** で保存しても使えます。
2. 初めての場合は操作チュートリアルから始めます。
3. 依頼と対象期間を確認し、**Threat Hunting** で関連するイベントを探します。
4. イベント詳細と元ログ、資料を読み、判断を支えるイベントを証拠に追加します。
5. 判定・優先度・主な対応・対象端末を選び、事実と次の対応を記録して提出します。
6. 自分の報告と模範例を比較し、復習または次の演習へ進みます。

保存したHTMLには画面、プログラム、教材データを同梱しています。利用時の外部ライブラリー、フォント、API、ネットワーク接続は不要です。オンライン版を最初に開くときや公式資料を参照するときはインターネット接続が必要です。

## 学習内容

操作チュートリアル1件と調査演習6件を収録しています。

| 段階 | 件数 | 学ぶこと |
| --- | --- | --- |
| 操作チュートリアル | 1 | 期間指定、検索、詳細、証拠登録、資料、報告の基本操作 |
| ガイド付き | 2 | 調べる理由を確認しながら、ログと承認資料を照合する |
| チェックリスト | 2 | 必要な調査を組み立て、不審な変更や監視の途絶を確認する |
| 自力で調査 | 2 | 背景イベントから必要な情報を選び、判断と引継ぎをまとめる |

認証、アカウント・サービスの変更、監視の途絶、ファイル変更を題材にしています。インシデント、正当な作業、情報不足で判断を保留するケースを含みます。アラートのレベルだけで判定せず、時刻、対象、ログの内容、承認範囲、収集できた情報を照合します。

全7件とも時間制限はなく、どの演習からでも始められます。各ケースには背景イベントと3段階のヒントがあり、最後のヒントには解答の手掛かりや判断例も含みます。報告を一度提出すると、合否にかかわらず報告例を開けます。ヒントや報告例を見ることによる減点はありません。自力で考えてから比較したい場合は、必要になるまで開かずに進めてください。

証拠は必要なものに絞って提出します。証拠欄の数字は「選択数 / 上限」で、上限まで選ぶ必要はありません。すべてのイベントを証拠に選ぶだけではクリアできません。自由記述は入力の形式を確認するもので、文章の意味や推論の正しさを自動採点しません。模範例との比較に使ってください。この教材は自己学習用で、試験の成績評価や不正防止を目的としていません。

## 画面と検索

- **Overview**：ケースのイベント集計を確認します。
- **Endpoints**：エージェント一覧で対象端末と接続状態を確認し、端末のイベントへ進みます。
- **Threat Hunting**：DQLの対応構文、期間、フィールドのフィルターを使ってイベントを調べます。詳細とJSON・元ログを確認できます。
- **File Integrity Monitoring**：同じ教材のファイル変更イベントを調べます。
- **学習パネル**：問題文、ヒント、資料、証拠、報告、振り返りを扱います。これらはroom独自の教材機能です。

時刻はUTCです。教材の固定された時刻を使うため、現実の現在時刻やブラウザのタイムゾーンとは分けて扱います。期間外のイベントは表示されません。

### イベント検索：DQLの一部

対応例：

```text
agent.id: "001"
rule.level >= 8
agent.id: "001" and rule.level >= 8
rule.groups: "authentication_failed" or rule.groups: "authentication_success"
not syscheck.path:*
(agent.id: "001" or agent.id: "002") and rule.level >= 5
```

フィールド指定、引用符付きの値、数値比較、`and` / `or` / `not`（大文字も可）、かっこ、フィールドの存在確認、対応する文字列フィールドの `*` を使えます。条件をつなぐ際は `and` または `or` を明示してください。

識別子などのkeyword型は大小文字を区別した完全一致で、引用符なしの `*` をワイルドカードとして使えます。`full_log`、`rule.description`、`data.command`、`data.win.eventdata.commandLine` は大小文字を区別しない部分一致に簡略化しています。実際のOpenSearchの全文検索解析と同じ動作ではありません。

`rule.level`、`data.srcport`、`data.win.eventdata.logonType` など、この教材で数値型にしたフィールドは、`data.srcport: 43104` や `data.win.eventdata.logonType: 10` のように引用符なしの数値で検索します。`data.srcport: "43104"` は本教材ではエラーです。実機のイベントではポート番号やlogonTypeが文字列で出力される場合があり、検索時の扱いはインデックスのマッピングにも依存します。本教材の型を実機のすべてのフィールドへ当てはめないでください。

Windowsのパスや `ドメイン名\ユーザー名` を検索する場合は値を引用符で囲み、バックスラッシュ1文字を `\\` と入力します。

```text
data.win.eventdata.imagePath: "C:\\Program Files\\OpsInventory\\agent.exe"
data.win.eventdata.memberName: "WIN-FIN-01\\maint-fin"
```

検索対象は教材で定義したフィールドです。フィールド名を付けない自由検索、Lucene、正規表現、スクリプト、任意のフィールド定義など、検索エンジン全体は再現していません。

### エージェント検索：WQLの一部

```text
status=active
status=disconnected and os.platform=ubuntu
name~web
(id=001 or id=002) and status=active
```

WQLはイベント検索のDQLとは異なります。教材では `id`、`name`、`ip`、`status`、`os.name`、`os.platform` を対象に、`=`（一致）、`!=`（不一致）、`~`（部分一致）と小文字の `and` / `or`、かっこを使えます。比較は大小文字を区別します。`>` / `<` はこの教材の文字列フィールドでは辞書順の比較です。WQLの `*` ワイルドカードは使えません。不正な構文や未対応の構文はエラーとして表示します。

## 日本語・英語

初回はブラウザの優先言語が日本語なら日本語、それ以外は英語で開始します。言語メニューで選び直せます。問題文、説明、ヒント、資料、報告例を両言語で用意しています。

言語を切り替えても検索条件、証拠、進捗、入力中の報告は保持します。フィールド名、ログ本文、識別子は両言語共通です。自分で書いた報告文を自動翻訳・上書きしません。

## 保存と報告

進捗はこのroom専用の保存領域に自動保存します。ブラウザの制約やローカルファイルの扱いによっては自動保存を利用できないため、**保存**で進捗JSONを残してください。別のブラウザ・端末・オンライン版へ移す場合は、そのJSONを**読込**で取り込みます。完了後に報告の下書きを書き換えても、正答時の完了記録を保持します。

読込時は、**現在の進捗をバックアップ**を押してから**読み込んで置き換える**を選びます。ブラウザのダウンロードが完了したことを確認してください。確認画面を閉じた場合や、不正な保存ファイルの場合は現在の進捗を置き換えません。SOCroomなど、ほかのroomの保存ファイルは読み込めません。提出後の**報告を書き出す**では、入力中の調査記録をテキストとして保存できます。

## 再現の範囲

Wazuh **4.14系の画面・用語・公開資料**を参考にした、非公式の独立した教材です。Wazuh社による提供・認定・支援を意味しません。公式ロゴや公式UIのソースコードは同梱していません。

実際のWazuh、OpenSearch、エージェント、OSは動作していません。イベントは架空の合成データで、教材用のカスタムルールID（100001以降）を使います。標準ルールによる実際の検知結果ではありません。収集対象や観測の限界は各ケースの資料で確認してください。

実機との全画面・全操作の一致は検証していません。エージェントの導入、実ログの配送、ルールの実行、Active Response、端末隔離、実環境の負荷や検知精度を練習・検証する教材ではありません。実機に進む際は、利用するバージョンと収集設定を公式資料で確認してください。

## English

Wazuhroom is a browser-based educational simulation for practicing the basic SOC workflow with Wazuh-style screens: review an alert, choose a time range, filter events, inspect details and raw logs, cross-check reference material, and record a supported decision and handover. Learners do not need to run Wazuh or prepare monitored endpoints.

This is an independent optional room. It sits outside the main room-series learning path. No previous room or imported progress is required.

### Getting started

1. Open [Play Now](https://retiacole.github.io/wazuhroom/), or save [wazuhroom.html](https://github.com/retiacole/wazuhroom/blob/main/wazuhroom.html) using **Download raw file** and open the saved HTML in a browser.
2. Start with the interface tutorial.
3. Read the assignment and time window, then investigate in **Threat Hunting**.
4. Inspect event details, raw logs, and reference documents. Add the events that support your conclusion as evidence.
5. Choose a verdict, priority, primary action, and endpoint. Write the observed facts and next steps, then submit.
6. Compare your report with the worked example and continue or review.

The saved HTML includes the application and all teaching data. No installation, account, external libraries, fonts, APIs, or runtime network access is required. Opening the online version or following reference links requires an Internet connection.

### Course and screens

There is **one interface tutorial and six investigation cases**: two guided, two with checklists, and two independent. Topics include authentication, account and service changes, monitoring gaps, and file changes. The cases cover incidents requiring escalation, authorized work, and insufficient evidence. There are no time limits; start anywhere. Each case includes background events and three levels of hints. The final hint may include solution clues or an expected decision. After any report submission, whether it passes or fails, you can open the example report. Viewing hints or examples carries no penalty. Leave them closed until needed if you prefer to investigate independently first.

Use **Overview** for summaries, **Endpoints** for agent and endpoint status, **Threat Hunting** for event searches and details, and **File Integrity Monitoring** for file-change events. The separate learning panel contains assignments, hints, documents, evidence, reports, and reflection; these are Wazuhroom teaching features.

All times are UTC and belong to a fixed teaching timeline. Events outside the selected time range are hidden. Select relevant evidence rather than every event. The evidence counter means **selected / maximum**, not a required count; you do not need to fill the allowance. Report text receives structural checks only: the application does not judge its meaning or reasoning quality. Compare your writing with the worked example. This is a self-study course, not a graded examination or an anti-cheating system.

### Search, language, and saves

Event search supports a documented **DQL subset**: field comparisons, quoted values, numeric ranges, `and` / `or` / `not` (also uppercase), parentheses, field existence, and unquoted `*` on supported keyword fields. Join conditions with an explicit `and` or `or`. The examples above apply in both languages.

Keyword fields use case-sensitive exact matching. Searches in `full_log`, `rule.description`, `data.command`, and `data.win.eventdata.commandLine` use simplified case-insensitive substring matching, which does not reproduce OpenSearch's full-text analyzer. Unqualified free-text searches, Lucene, regular expressions, scripts, arbitrary mappings, and a complete search backend are not included.

Fields modeled as numbers here, including `rule.level`, `data.srcport`, and `data.win.eventdata.logonType`, require unquoted numbers: for example, `data.srcport: 43104` or `data.win.eventdata.logonType: 10`. The simulator rejects `data.srcport: "43104"`. Real event payloads may represent ports or logonType as strings, and query behavior also depends on the index mapping. Do not generalize this simulator's field types to every real deployment.

For Windows paths and `DOMAIN\user` values, use a quoted value and enter `\\` for each literal backslash. The two Windows examples in the Japanese section above work in either language.

Agent search uses a separate **WQL subset** over `id`, `name`, `ip`, `status`, `os.name`, and `os.platform`. Use `=` (equal), `!=` (not equal), `~` (substring), lowercase `and` / `or`, and parentheses. Comparisons are case-sensitive; `>` / `<` compare these string fields lexicographically in this simulator. WQL does not accept `*` wildcards. Invalid or unsupported syntax produces an error.

The initial language follows the browser's preferred language: Japanese for Japanese browsers and English otherwise. You can switch languages without losing searches, selected evidence, progress, or draft reports. Field names, original logs, and identifiers remain unchanged. Your own writing is not translated or overwritten.

Progress is saved in this room's own browser storage. Local-file restrictions or browser settings may prevent automatic saves; export a progress JSON using **Save** as a portable backup. Use **Load** to transfer it to another browser, device, or the online version. Choose **Back up current progress**, check that the browser completed the download, then select **Import and replace**. Closing the import dialog or loading invalid data leaves the current progress unchanged. Other rooms' save files are not compatible. Editing a draft after completion retains the earlier successful completion record. After submission, **Export report** saves the current investigation draft as readable text.

### Scope

This unofficial, independent simulator references **Wazuh 4.14** UI concepts, terminology, and public documentation. It is not provided, certified, or endorsed by Wazuh. It does not bundle the official logo or UI source code.

Wazuh, OpenSearch, agents, and operating systems do not run inside this application. All events are synthetic and use teaching-specific custom rule IDs starting at 100001. They are not recorded detections from the standard Wazuh ruleset. Each case explains its assumed collection settings and visibility limits.

Full screen-by-screen and operation-by-operation equivalence with a live Wazuh deployment has not been verified. Agent deployment, real log delivery, rules execution, Active Response, endpoint isolation, production performance, and detection accuracy are outside this course. Check the official documentation for the version and configuration you use when moving to a real environment.

## 開発 / Development

Node.js 22以上を使用します。 / Use Node.js 22 or later.

```sh
npm ci
npm run build
npm test
```

依存関係の取得後は、直接実行することもできます。 / After installing development dependencies, you can also run:

```sh
node build.js
node --test
```

| Path | 内容 / Purpose |
| --- | --- |
| `src/content.js` | 和英の教材・合成イベント / Bilingual cases and synthetic events |
| `src/engine.js` | 検索、採点、保存検証 / Search, assessment, and save validation |
| `src/app.js` | 画面と操作 / Interface and interaction |
| `src/style.css` | 表示 / Styling |
| `build.js` | 単体HTML生成 / Standalone HTML build |
| `tests/` | 教材・検索・採点等の検証 / Content, search, and assessment checks |
| `docs/REFERENCES.md` | 参照資料と再現範囲 / References and fidelity notes |

配布用の `wazuhroom.html`、`docs/index.html`、`docs/wazuhroom.html` は同じ内容です。生成後のHTMLを直接編集せず、`src/` の編集後にビルドしてください。

The three distribution files contain the same standalone application. Edit the sources and rebuild instead of editing generated HTML.

開発用のDOMテストだけでjsdomを使用します。配布HTMLには外部ライブラリーを読み込む処理はありません。自動検証は、日英の全7件の画面操作・検索・採点・保存を対象にしています。v0.1.0公開時の実ブラウザ確認は、調査から報告、保存と復元、幅390pxと1440pxの表示を対象にしました。v0.1.1では57件の自動テストを通過し、旧版の保存データの復元も確認しました。実ブラウザで必須資料・手順の表示、英語の検索ヘルプと数値検索、幅390pxの報告画面を確認しています。Firefox・Safariの実機検証は未実施です。

jsdom is used only for development tests. The distributed HTML loads no external libraries. Automated checks cover all seven cases in both languages, UI operations, search, assessment, and saves. Browser checks for the v0.1.0 release covered investigation through reporting, export/import, and 390px/1440px layouts. Version 0.1.1 passes 57 automated tests, including restoration of v0.1.0 saves. Browser checks cover required references and instructions, English search help and numeric search, and the report at 390px width. Firefox and Safari have not been directly tested.

## ライセンスと謝辞 / License and acknowledgments

このプロジェクトの独自実装はMIT Licenseで公開しています。詳細は [LICENSE](LICENSE) を参照してください。このMITライセンスは、Wazuhの名称・商標・ブランド素材の利用許諾を与えるものではありません。

This project's original implementation is released under the MIT License; see [LICENSE](LICENSE). That license does not grant permission to use Wazuh's name, trademarks, or branding materials.

WazuhはWazuh Inc.の商標です。本教材はWazuh Inc.とは提携しておらず、同社による提供・認定・承認・支援を示すものではありません。名称や画面の利用について、許可取得済み・権利確認完了と表明するものでもありません。[Wazuhの商標・ブランドポリシー](https://wazuh.com/docs/legal-resources/Trademark_and_Brand_Policy_May_2024.pdf)を参照してください。

Wazuh is a trademark of Wazuh Inc. This project is not affiliated with Wazuh Inc. and is not provided, certified, approved, or endorsed by the company. This notice does not assert that permission has been obtained or that use of the name or interface has received legal clearance. See [Wazuh's Trademark and Brand Policy](https://wazuh.com/docs/legal-resources/Trademark_and_Brand_Policy_May_2024.pdf).

正解もHTMLに含む自己学習用教材です。ヒント・報告例は学習のために利用でき、不正防止を目的とする試験システムではありません。

Answers are included in the HTML for self-study. Hints and example reports are learning aids; this is not an examination system designed to prevent cheating.

[SOCroom](https://github.com/retiacole/socroom)の「証拠を選び、判断し、報告する」という教育設計を参考にしています。Wazuhの画面・検索・データ形式の参照元は[参考資料](docs/REFERENCES.md)にまとめています。

The course draws on SOCroom's teaching approach of selecting evidence, making a decision, and reporting it. Official references for Wazuh screens, searches, and data formats are listed in [References](docs/REFERENCES.md).

Created with AI assistance from OpenAI Codex.
