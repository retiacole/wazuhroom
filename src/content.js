(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WazuhContent = factory();
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const B = (ja, en) => ({ ja, en });
  const copy = value => JSON.parse(JSON.stringify(value));
  const iso = (date, clock) => `${date}T${clock}:00.000Z`;
  const profiles = [
    { id: '001', name: 'web-01', ip: '10.20.1.11', os: { name: 'Ubuntu', platform: 'ubuntu', version: '24.04' } },
    { id: '002', name: 'win-fin-01', ip: '10.20.2.21', os: { name: 'Microsoft Windows 11', platform: 'windows', version: '24H2' } },
    { id: '003', name: 'db-01', ip: '10.20.3.31', os: { name: 'Debian', platform: 'debian', version: '12' } }
  ];

  function agentSnapshot(end, disconnected) {
    return profiles.map(profile => ({
      ...copy(profile),
      status: disconnected && profile.id === disconnected.id ? 'disconnected' : 'active',
      lastKeepAlive: disconnected && profile.id === disconnected.id ? disconnected.at : end
    }));
  }

  function event(id, timestamp, agentId, ruleId, level, description, groups, decoder, data, fullLog, extra) {
    const agent = profiles.find(item => item.id === agentId);
    return {
      id, timestamp,
      agent: { id: agent.id, name: agent.name, ip: agent.ip },
      rule: { id: String(ruleId), level, description, groups },
      decoder: { name: decoder }, data, full_log: fullLog,
      ...(extra || {})
    };
  }

  function ssh(id, timestamp, agentId, accepted, user, source, port, authenticationMethod) {
    const host = profiles.find(item => item.id === agentId).name;
    const data = { srcip: source, srcport: port || 42022, dstuser: user, action: accepted ? 'authentication_success' : 'authentication_failed' };
    const message = accepted
      ? `Accepted ${authenticationMethod || 'publickey'} for ${user} from ${source} port ${data.srcport} ssh2`
      : `Failed password for ${user} from ${source} port ${data.srcport} ssh2`;
    return event(id, timestamp, agentId, accepted ? 100011 : 100010, accepted ? 3 : 5,
      accepted ? 'Training: SSH authentication succeeded' : 'Training: SSH authentication failed',
      ['wazuhroom', 'sshd', accepted ? 'authentication_success' : 'authentication_failed'],
      'wazuhroom-sshd', data, `${timestamp} ${host} sshd[2481]: ${message}`);
  }

  function windows(id, timestamp, eventId, data, description, level, groups) {
    const system = { eventID: String(eventId), providerName: eventId === '7045' || eventId === '7036' ? 'Service Control Manager' : 'Microsoft-Windows-Security-Auditing', computer: 'win-fin-01', channel: eventId === '7045' || eventId === '7036' ? 'System' : 'Security' };
    const win = { system, eventdata: data };
    const rules = { '4624': 100020, '4720': 100021, '4732': 100022, '4733': 100023, '7045': 100024, '7036': 100025, '4688': 100026 };
    return event(id, timestamp, '002', rules[eventId], level, description,
      ['wazuhroom', 'windows', ...(groups || [])], 'wazuhroom-windows', { win }, JSON.stringify({ win }));
  }

  function background(caseId, from, to, cutoff) {
    const start = Date.parse(from);
    const span = Date.parse(to) - start;
    return Array.from({ length: 48 }, (_, index) => {
      const timestamp = new Date(start + Math.round((index + 1) * span / 50)).toISOString();
      let profile = profiles[index % profiles.length];
      if (cutoff && profile.id === cutoff.id && timestamp > cutoff.at) profile = profiles[index % 2];
      const id = `${caseId}-bg-${String(index + 1).padStart(2, '0')}`;
      if (profile.id === '002') {
        if (index % 2 === 0) return windows(id, timestamp, '4624', {
          targetUserName: 'svc.inventory', ipAddress: '10.20.0.5', logonType: 3
        }, 'Training: Windows authentication succeeded', 3, ['authentication_success', 'routine']);
        return windows(id, timestamp, '7036', {
          serviceName: 'Windows Event Log', action: 'running'
        }, 'Training: monitored service status', 3, ['service_status', 'routine']);
      }
      if (index % 2 === 0) return ssh(id, timestamp, profile.id, true, 'svc.inventory', '10.20.0.5', 41000 + index);
      return event(id, timestamp, profile.id, 100001, 3, 'Training: scheduled job completed',
        ['wazuhroom', 'scheduled_task', 'routine'], 'wazuhroom-scheduler',
        { dstuser: 'root', service: 'logrotate', action: 'job_completed' },
        `${timestamp} ${profile.name} room-scheduler: user=root job=logrotate result=completed`);
    });
  }

  const provenance = B(
    'このケースは架空の演習データです。rule.id 100001–100099 と wazuhroom-* decoder は教材専用で、Wazuh標準ルールの出力を実機で検証したものではありません。背景の正常動作も学習用カスタムルールによりlevel 3以上のイベントとして表示しています。実環境で同じ正常動作が必ずアラートになるとは限りません。IPアドレス・ユーザー名・ハッシュは架空です。全時刻はUTCで、期間内の選定ログだけを表示します。検索結果がないことは、未収集の動作や期間外の動作がなかった証明にはなりません。',
    'This case uses fictional training data. Rule IDs 100001–100099 and wazuhroom-* decoders are educational definitions, not outputs verified against a live Wazuh installation. Routine background activity is also represented as level 3 or higher events by training rules; the same activity need not produce alerts in a real deployment. IPs, users, and hashes are fictional. All times are UTC. Only selected logs in the case window are shown. An empty search does not prove that uncollected or out-of-window activity never occurred.'
  );
  const backgroundScope = B(
    '共通の背景ログ：Linux端末のweb-01とdb-01では、10.20.0.5からsvc.inventoryによるSSH公開鍵認証の成功、およびrootによるlogrotateの完了を収集します。Windows端末win-fin-01では、10.20.0.5からsvc.inventoryへのSecurity 4624（logonType 3：ネットワークログオン）と、Windows Event LogサービスのSystem 7036（稼働状態）を収集します。いずれもこの演習では定期運用です。監視欠落のケースでは、以下の最終観測・切断時刻が優先され、切断後のdb-01から背景ログは届きません。',
    'Common background coverage: Linux endpoints web-01 and db-01 provide successful SSH public-key authentication by svc.inventory from 10.20.0.5 and logrotate completion by root. Windows endpoint win-fin-01 provides Security 4624 events for svc.inventory from 10.20.0.5 (logonType 3: network logon) and System 7036 events reporting the Windows Event Log service running. These are routine operations in this exercise. In the collection-gap case, the last-observation and disconnect times below take precedence; no db-01 background telemetry arrives after disconnection.'
  );
  const runbook = B(
    '報告フォームの「判定」：「インシデント」はインシデント候補として引き継ぐ状態、「正当な活動」は承認済み作業と証拠が一致する状態、「判断保留」は判断に必要な観測が不足する状態です。「優先度」の「高」は不審な認証成功後の権限操作、承認外の自動起動サービス、重要な認証設定の承認外変更。「中」は予定時間を超えて復旧未確認の監視欠落。「低」は単独の認証失敗、または承認済み作業との一致です。「次の対応」は「担当へエスカレーション」（上位担当へ引継ぎ）、「追加確認を依頼」（担当者・収集経路へ確認）、「監視を継続」（記録を残して継続監視）から選びます。「主な対象」を選び、「確認した事実と根拠」には端末・時刻・根拠イベント・参照文書を、「未確認事項・引継ぎ先・次の確認」には分からないことと確認先を短く記入してください。rule.levelは調査の入口であり、侵害の確定や業務優先度そのものではありません。教材の報告・採点欄はWazuhroom独自機能です。',
    'Report form — Verdict: “Incident” means hand over an incident candidate; “Benign activity” means evidence matches approved work; “Insufficient evidence” means important observations are missing. Priority — “High”: suspicious successful authentication followed by privileged activity, an unapproved auto-start service, or an unapproved change to critical authentication configuration. “Medium”: a collection gap with recovery unconfirmed beyond its planned window. “Low”: a single authentication failure or activity matching approved work. Next action: choose “Escalate to the responsible team” for a responder handover, “Request verification” for checks with the owner or collection team, or “Continue monitoring” while retaining the record. Select the “Primary target”. In “Observed facts and evidence”, record the endpoint, time, supporting events, and references. In “Unknowns, recipient, and next checks”, state what is missing and who should check it. A rule level is a lead, not proof of compromise or the business priority itself. The report and scoring panel belongs to Wazuhroom, not the Wazuh product.'
  );

  function document(id, title, body) { return { id, title, body }; }
  function documents(caseId, scope, title, change, extra) {
    return [
      document(`${caseId}-scope`, B('収集範囲とデータの読み方', 'Collection scope and data notes'), B(`${backgroundScope.ja}\n\n${scope.ja}\n\n${provenance.ja}`, `${backgroundScope.en}\n\n${scope.en}\n\n${provenance.en}`)),
      document(`${caseId}-change`, title, change),
      document(`${caseId}-runbook`, B('SOC一次対応の判断基準', 'SOC triage policy'), runbook),
      ...(extra || [])
    ];
  }

  function step(caseId, kind, title, body) { return { id: `${caseId}-${kind}`, kind, title, body }; }
  function standardSteps(caseId, stage, target) {
    const result = [];
    if (stage === 'guided') {
      result.push(step(caseId, 'events', B('Threat Huntingのイベント一覧を開く', 'Open the Threat Hunting event list'), B('メニューのThreat Huntingからイベント一覧を開きます。課題パネルを見ただけでは操作は完了しません。', 'Open the event list from Threat Hunting in the menu. Viewing the task panel alone does not complete an operation.')));
      result.push(step(caseId, 'range', B('調査期間を適用する', 'Apply the investigation window'), B('開始・終了を確認し、期間を適用してください。すべてUTCです。時間を絞りすぎたらケースの期間に戻します。', 'Check and apply the start and end time. Times are UTC. Restore the case window if a narrow interval hides context.')));
    }
    result.push(step(caseId, 'search', B('関連ログを絞り込む', 'Filter related events'), B(`対象は${target}です。DQL検索またはフィルターを実行し、必要に応じて条件を外して前後の出来事を確認します。`, `Investigate ${target}. Run a DQL search or apply a filter, then remove conditions when needed to inspect surrounding activity.`)));
    result.push(step(caseId, 'detail', B('詳細と元ログを読む', 'Read details and the original log'), B('関係する行を展開して、agent、時刻、rule、data、full_logを確認します。表示されない項目は推測で補いません。', 'Expand a relevant row and inspect the agent, time, rule, data, and full_log. Do not invent values for absent fields.')));
    result.push(step(caseId, 'evidence', B('判断を支える証拠を選ぶ', 'Select supporting evidence'), caseId === 'mixed-auth'
      ? B('win-fin-01のログオンとサービス登録に加え、比較対象であるweb-01の認証失敗を少なくとも1件、証拠に追加してください。両端末の出来事を比較した根拠を残し、同時刻というだけで関係を断定しないようにします。', 'Add evidence for the win-fin-01 logon and service registration, plus at least one authentication failure from web-01 as comparison evidence. Keep the records used to compare the endpoints; time overlap alone must not establish a connection.')
      : B('結論に必要なイベントを証拠として追加します。大量の正常ログを選ぶより、出来事のつながりを説明できる少数の記録を選びます。', 'Add the events needed to support your conclusion. Prefer a few records that explain the sequence over many unrelated routine events.')));
    result.push(step(caseId, 'document', B('資料と判断基準を読む', 'Read references and the triage policy'), B('収集範囲、作業記録、SOC一次対応の判断基準を読みます。', 'Read the collection scope, work records, and SOC triage policy.')));
    result.push(step(caseId, 'report', B('根拠付きで一次報告する', 'Submit an evidence-based report'), B('「判定」「優先度」「次の対応」「主な対象」を選びます。「確認した事実と根拠」に観測事実を、「未確認事項・引継ぎ先・次の確認」に分からないことと誰に何を確認するかを書いて報告してください。', 'Select “Verdict”, “Priority”, “Next action”, and “Primary target”. Record observations in “Observed facts and evidence”. Use “Unknowns, recipient, and next checks” to state what is missing and who should check what next.')));
    return result;
  }

  function assemble(config) {
    const events = background(config.id, config.timeRange.from, config.timeRange.to, config.disconnected)
      .concat(config.events).sort((a, b) => a.timestamp.localeCompare(b.timestamp) || a.id.localeCompare(b.id));
    const { disconnected, ...rest } = config;
    const steps = config.steps.map(item => item.kind !== 'document' ? item : {
      ...item,
      body: B(
        `「資料」タブで${config.documents.map(doc => `「${doc.title.ja}」`).join('、')}を開いて読みます。開いた資料は「確認済み」と表示されます。判断基準を確認し、ログと資料の端末・時刻・利用者・対象を照合してください。`,
        `In the References tab, open and read ${config.documents.map(doc => `“${doc.title.en}”`).join(', ')}. Opened references are labelled “Opened”. Review the triage policy and compare the endpoint, time, account, and target with the logs.`
      )
    });
    return { ...rest, agents: agentSnapshot(config.timeRange.to, disconnected), events, steps };
  }

  const tutorialId = 'tutorial';
  const tutorial = assemble({
    id: tutorialId, stage: 'tutorial',
    title: B('操作入門：1件の認証失敗を調べる', 'First investigation: one failed login'),
    brief: B('web-01でSSH認証失敗が1件通知されました。画面を操作して事実を読み取り、判断できる範囲を報告しましょう。ここでは正解を急がず、検索から証拠・文書・報告までの一連の流れを体験します。', 'An SSH authentication failure was reported on web-01. Use the interface to inspect the facts and report what can be concluded. Practise the complete search, evidence, document, and reporting workflow.'),
    objectives: [
      B('期間・検索・フィルターで必要なイベントを探す', 'Find relevant events using time, search, and filters'),
      B('詳細のフィールドと元ログを読み、証拠に保存する', 'Read structured fields and the original log, then save evidence'),
      B('認証失敗と侵害成功を区別して一次報告する', 'Distinguish a failed login from a successful compromise')
    ],
    timeRange: { from: iso('2026-10-14', '09:00'), to: iso('2026-10-14', '09:30') },
    hints: [
      B('Threat Huntingのイベント一覧を開き、ケースの期間を適用してから agent.name: "web-01" を検索してみましょう。', 'Open the Threat Hunting event list, apply the case time window, then try agent.name: "web-01".'),
      B('data.action: "authentication_failed" を追加すると通知対象が見つかります。行を開いて data.srcip と data.dstuser を読みます。', 'Add data.action: "authentication_failed" to find the reported event. Expand it and read data.srcip and data.dstuser.'),
      B('1件の失敗は認証成功の証拠ではありません。証拠1件と収集範囲・引継ぎ文書をそろえ、判断基準を確認して「判断保留」／「低」／「追加確認を依頼」、主な対象「web-01 (001)」で報告できます。', 'A single failure is not proof of successful access. Keep that event plus the scope and handover documents, read the triage policy, and select “Insufficient evidence” / “Low” / “Request verification” with primary target “web-01 (001)”.')
    ],
    documents: documents(tutorialId,
      B('対象期間は2026-10-14 09:00–09:30 UTC。web-01とdb-01はSSH認証ログと定期処理の選定ログ、win-fin-01はSecurity/Systemの選定イベントを収集します。失敗と成功は別のactionです。パケット、認証基盤全体、実行プロセス一覧はありません。10.20.0.5のsvc.inventoryは定期収集用アカウントです。', 'Window: 2026-10-14 09:00–09:30 UTC. Selected SSH and scheduled-job logs are collected from web-01 and db-01; selected Security/System events come from win-fin-01. Failures and successes have different actions. Packet data, complete identity logs, and process inventories are unavailable. svc.inventory from 10.20.0.5 is the scheduled collection account.'),
      B('当番への引継ぎ：単独の認証失敗', 'Shift handover: an isolated authentication failure'),
      B('通知は09:12 UTC、web-01のdeployへの失敗。203.0.113.44は登録された運用接続元ではありませんが、所有者・利用者・地域はこの資料では特定できません。この時間帯のweb-01変更予定はありません。当番は端末担当者への確認と、追加の失敗・成功ログの有無の確認を依頼しています。登録外IPだけで侵害確定とはしません。', 'The notification concerns a failed login for deploy on web-01 at 09:12 UTC. 203.0.113.44 is not a registered operations source; this record does not identify its owner, user, or location. No web-01 change is planned in this window. The shift owner requests verification with the endpoint owner and a check for additional failures or successes. An unregistered IP alone does not establish compromise.')),
    events: [ssh('tutorial-failure', iso('2026-10-14', '09:12'), '001', false, 'deploy', '203.0.113.44')],
    steps: [
      step(tutorialId, 'events', B('1. Threat Huntingのイベント一覧を開く', '1. Open the Threat Hunting event list'), B('メニューからThreat Huntingを選び、イベント一覧を表示します。中央がWazuh風の調査画面、こちらが教材ガイドです。', 'Choose Threat Hunting to display the event list. The central area is the Wazuh-style investigation interface; this panel is the learning guide.')),
      step(tutorialId, 'range', B('2. 調査期間を適用する', '2. Apply the time window'), B('2026-10-14 09:00–09:30 UTCを確認して期間を適用します。実機でも、時間条件が違うと同じ検索でも結果が変わります。', 'Check and apply 2026-10-14 09:00–09:30 UTC. On a real system, a different time filter changes the results of the same query.')),
      step(tutorialId, 'search', B('3. web-01の失敗を検索する', '3. Search failures on web-01'), B('agent.name: "web-01" AND data.action: "authentication_failed" を入力して検索します。イベントの検索はDQLです。Endpoints画面のWQLとは記法が異なります。', 'Search for agent.name: "web-01" AND data.action: "authentication_failed". The event list uses DQL; the Endpoints screen uses a different syntax called WQL.')),
      step(tutorialId, 'detail', B('4. 行を展開して詳細を読む', '4. Expand and inspect the event'), B('09:12の行を展開し、agent.name、rule.level、data.srcip、data.dstuser、full_logを読みます。認証の「失敗」を示す記録であることを確かめてください。', 'Expand the 09:12 row. Read agent.name, rule.level, data.srcip, data.dstuser, and full_log. Confirm that it records a failed authentication.')),
      step(tutorialId, 'evidence', B('5. イベントを証拠に追加する', '5. Add the event as evidence'), B('この認証失敗イベントを証拠に追加します。背景の定期処理まで選ぶ必要はありません。証拠は後から取り消せます。', 'Add the failed-login event to the evidence list. Routine background jobs are unnecessary. You can remove selected evidence later.')),
      step(tutorialId, 'document', B('6. 資料と判断基準を読む', '6. Read references and the triage policy'), B('収集範囲、引継ぎ、SOC一次対応の判断基準を読みます。', 'Read the collection scope, handover, and SOC triage policy.')),
      step(tutorialId, 'report', B('7. 一次報告を提出する', '7. Submit the initial report'), B('「判定」は「判断保留」、「優先度」は「低」、「次の対応」は「追加確認を依頼」、「主な対象」は「web-01 (001)」を選びます。「確認した事実と根拠」には時刻・接続元・失敗した利用者・成功は確認できないことを、「未確認事項・引継ぎ先・次の確認」には端末担当者への確認事項を書き、「調査報告を提出」を押します。', 'Choose “Insufficient evidence” for “Verdict”, “Low” for “Priority”, “Request verification” for “Next action”, and “web-01 (001)” for “Primary target”. In “Observed facts and evidence”, state the time, source, target account, and that success is not established. In “Unknowns, recipient, and next checks”, describe the checks for the endpoint owner. Select “Submit investigation report”.'))
    ],
    answer: {
      verdict: 'unknown', priority: 'low', action: 'verify', target: '001',
      evidenceGroups: [['tutorial-failure']], documentIds: ['tutorial-scope', 'tutorial-change'],
      facts: B('09:12 UTC、web-01のdeployに対し203.0.113.44からSSH認証失敗を観測した。単独の失敗であり、この証拠はログイン成功や侵害を示さない。接続元の所有者と期間外の行動は不明。', 'At 09:12 UTC, web-01 recorded a failed SSH login for deploy from 203.0.113.44. This isolated failure does not establish a successful login or compromise. The source owner and activity outside the window are unknown.'),
      nextStep: B('端末担当者に該当接続の心当たりを確認し、収集範囲を確認したうえで前後の認証ログを追加調査する。繰り返しや成功を認めた場合は優先度を見直す。', 'Ask the endpoint owner about the connection, confirm collection coverage, and inspect surrounding authentication records. Reassess priority if repetition or a successful login is found.'),
      explanation: B('操作・証拠・文書をひと続きに使うのがこの演習の目的です。失敗アラートから攻撃者や侵害成功を断定せず、確認が必要な状態として引き継ぎます。', 'The goal is to connect interface operations, evidence, and documents. Do not infer an attacker identity or successful compromise from a failed-login alert; hand over the remaining verification needs.')
    }
  });

  const authId = 'auth-chain';
  const auth = assemble({
    id: authId, stage: 'guided',
    title: B('ガイド調査：認証失敗の後に何が起きたか', 'Guided: what followed the failed logins?'),
    brief: B('web-01の認証失敗が増加しています。失敗だけで検索を止めず、同じ接続元・利用者の成功と、その後の権限操作を追って一次報告してください。', 'Failed logins increased on web-01. Follow the source and account into successful authentication and subsequent privileged activity, then submit an initial report.'),
    objectives: [B('失敗から成功へ検索条件を広げる', 'Broaden a failure search to include successes'), B('接続元・利用者・時刻を照合して時系列を作る', 'Build a timeline using source, account, and time'), B('観測事実と攻撃者に関する推測を分けて引き継ぐ', 'Escalate observed facts separately from attribution assumptions')],
    timeRange: { from: iso('2026-10-15', '10:00'), to: iso('2026-10-15', '10:40') },
    hints: [
      B('agent.name: "web-01" AND data.action: "authentication_failed" で失敗の接続元を見つけます。', 'Use agent.name: "web-01" AND data.action: "authentication_failed" to identify the source.'),
      B('失敗条件を外し data.srcip: "203.0.113.77" で成功も探します。その後はagent.nameで端末全体のログへ戻ります。', 'Remove the failure condition and search data.srcip: "203.0.113.77" for successes too. Then return to all activity on the endpoint using agent.name.'),
      B('10:12–10:14の失敗、10:16の成功、10:18のopsによるuseradd実行を証拠にし、作業予定と照合します。sudoログには接続元IPがありません。同じ人物の実行とまでは断定できません。', 'Select failures at 10:12–10:14, the success at 10:16, and the useradd execution by ops at 10:18, then compare approved work. The sudo event has no source IP, so it does not by itself prove the same person performed it.')
    ],
    documents: documents(authId,
      B('対象期間は2026-10-15 10:00–10:40 UTC。web-01はSSH認証ログとsudo実行ログを収集します。sudo記録には実行アカウントとコマンドがあり、元のSSH接続IDはありません。ユーザー作成の最終結果、全プロセス、外部への通信は未収集です。10.20.0.5のsvc.inventoryは定期作業です。', 'Window: 2026-10-15 10:00–10:40 UTC. web-01 provides SSH authentication and sudo execution logs. sudo records an account and command, but no originating SSH session ID. The final account-creation result, complete processes, and outbound traffic are not collected. svc.inventory from 10.20.0.5 is routine activity.'),
      B('作業予定と運用接続元一覧', 'Approved work and operations sources'),
      B('この時間帯にweb-01のアカウント追加は承認されていません。運用接続は10.20.0.8の踏み台から行う手順で、203.0.113.77は登録外です。ops担当者はこの時間帯のweb-01への接続を予定していません。db-01のlogrotateと定期インベントリ収集は通常運用です。IPの登録状態は接続元人物を特定する情報ではありません。', 'No account addition is approved on web-01 during this window. Operations should connect through jump host 10.20.0.8; 203.0.113.77 is unregistered. The ops owner has no planned web-01 session in this period. logrotate on db-01 and scheduled inventory collection are routine. The IP registry does not identify the person behind a connection.')),
    events: [
      ssh('auth-chain-fail-1', iso('2026-10-15', '10:12'), '001', false, 'ops', '203.0.113.77', 43101),
      ssh('auth-chain-fail-2', iso('2026-10-15', '10:13'), '001', false, 'ops', '203.0.113.77', 43102),
      ssh('auth-chain-fail-3', iso('2026-10-15', '10:14'), '001', false, 'ops', '203.0.113.77', 43103),
      ssh('auth-chain-success', iso('2026-10-15', '10:16'), '001', true, 'ops', '203.0.113.77', 43104, 'password'),
      event('auth-chain-sudo', iso('2026-10-15', '10:18'), '001', 100012, 10, 'Training: privileged account-management command', ['wazuhroom', 'sudo', 'account_management'], 'wazuhroom-sudo',
        { srcuser: 'ops', dstuser: 'root', action: 'privileged_command', command: '/usr/sbin/useradd -m support-temp' },
        '2026-10-15T10:18:00Z web-01 sudo: ops : TTY=pts/2 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/sbin/useradd -m support-temp')
    ],
    steps: standardSteps(authId, 'guided', 'web-01'),
    answer: {
      verdict: 'incident', priority: 'high', action: 'escalate', target: '001',
      evidenceGroups: [['auth-chain-fail-1', 'auth-chain-fail-2', 'auth-chain-fail-3'], ['auth-chain-success'], ['auth-chain-sudo']], documentIds: ['auth-chain-scope', 'auth-chain-change'],
      facts: B('web-01で203.0.113.77からopsへの失敗を複数観測し、10:16 UTCに同じ接続元・利用者の成功を観測した。10:18にopsがrootとしてuseraddを実行した記録があり、作業予定にない。sudoとSSHを結ぶ接続ID、作成完了、実行人物、外部通信は確認できない。', 'web-01 recorded repeated failures for ops from 203.0.113.77, followed by a success for the same source/account at 10:16 UTC. At 10:18, ops executed useradd as root; this was not approved. No session ID links sudo to SSH, and account creation completion, actor identity, and outbound traffic are unconfirmed.'),
      nextStep: B('上位担当へ高優先度で引き継ぎ、該当期間の認証・sudo記録を保全する。ops担当者の実施確認、追加アカウントの状態、他端末への同接続元のアクセスを確認し、封じ込めの要否を判断してもらう。', 'Escalate at high priority and preserve the authentication and sudo records. Request confirmation from the ops owner, verify the additional account, inspect the same source across other endpoints, and have the responder decide containment.'),
      explanation: B('失敗の多さだけでなく、成功と承認外の権限操作が続いていることが引継ぎの根拠です。アカウント名の一致から調査仮説は立てられますが、人物や同一セッションまで確定したとは報告しません。', 'The escalation rests on successful access followed by unapproved privileged activity, not merely the volume of failures. Matching account names support a hypothesis, not a proven actor identity or shared session.')
    }
  });

  const adminId = 'approved-admin';
  const admin = assemble({
    id: adminId, stage: 'guided',
    title: B('ガイド調査：管理者追加は承認されているか', 'Guided: was the administrator addition approved?'),
    brief: B('win-fin-01でローカル管理者グループへの追加が通知されました。誰が、どのアカウントを、いつ追加したかを確認し、作業票の範囲と照合してください。', 'A local Administrators group addition was reported on win-fin-01. Identify the actor, added account, and time, then compare them with the approved change.'),
    objectives: [B('Windowsイベントの実行者と対象ユーザーを区別する', 'Distinguish the actor from the target in Windows events'), B('作成・グループ追加・削除を同一対象で追う', 'Follow creation, group addition, and removal for one account'), B('重要な変更でも承認と一致する場合の記録を残す', 'Document sensitive activity that matches approved work')],
    timeRange: { from: iso('2026-10-16', '11:00'), to: iso('2026-10-16', '11:40') },
    hints: [
      B('agent.name: "win-fin-01" AND (data.win.system.eventID: "4720" OR data.win.system.eventID: "4732" OR data.win.system.eventID: "4733") を検索します。', 'Search agent.name: "win-fin-01" AND (data.win.system.eventID: "4720" OR data.win.system.eventID: "4732" OR data.win.system.eventID: "4733").'),
      B('subjectUserNameは操作したアカウントです。4732のtargetUserNameは追加先グループで、memberNameが追加対象です。作業票のmaint-finと照合します。', 'subjectUserName is the actor. In event 4732, targetUserName is the destination group and memberName is the added member. Compare maint-fin with the change ticket.'),
      B('作成、Administrators追加、グループからのメンバー削除の3件を証拠にします。対象・実行者・時間がCHG-204と一致し、メンバー削除も確認できるため「正当な活動」／「低」／「監視を継続」です。', 'Keep creation, addition to Administrators, and removal of that membership. The target, actor, and time match CHG-204, including membership removal, so select “Benign activity” / “Low” / “Continue monitoring”.')
    ],
    documents: documents(adminId,
      B('対象期間は2026-10-16 11:00–11:40 UTC。win-fin-01はSecurityイベント4720（アカウント作成）、4732（ローカルグループへのメンバー追加）、4733（ローカルグループからのメンバー削除）を選定収集します。subjectUserNameは実行アカウント、memberNameはグループ操作の対象です。アカウント作成と管理者グループ加入は別の事象です。4733はグループ所属の削除を示し、アカウントやグループ自体の削除ではありません。', 'Window: 2026-10-16 11:00–11:40 UTC. Selected win-fin-01 Security events include 4720 (account creation), 4732 (member addition to a local group), and 4733 (member removal from a local group). subjectUserName is the actor; memberName is the affected group member. Account creation and administrator membership are distinct. Event 4733 removes membership; it does not mean the account or group itself was deleted.'),
      B('承認済み作業票 CHG-204', 'Approved change CHG-204'),
      B('対象：win-fin-01。担当アカウント：admin.mori。作業時間：11:10–11:30 UTC。会計ソフト更新のためローカルアカウントmaint-finを作成し、一時的にAdministratorsへ追加してよい。11:30までに同グループから外し、アカウントは通常権限で残す。別端末、別アカウント、時間外の管理者追加はこの承認に含まれない。作業後は記録を保存し継続監視する。', 'Endpoint: win-fin-01. Operator account: admin.mori. Window: 11:10–11:30 UTC. Create local account maint-fin and temporarily add it to Administrators for an accounting-software update. Remove membership by 11:30; retain the account with normal privileges. Other endpoints, accounts, or times are outside this approval. Preserve the record and continue monitoring after completion.')),
    events: [
      windows('approved-admin-created', iso('2026-10-16', '11:12'), '4720', { subjectUserName: 'admin.mori', targetUserName: 'maint-fin', targetDomainName: 'WIN-FIN-01' }, 'Training: local account created', 5, ['account_management']),
      windows('approved-admin-added', iso('2026-10-16', '11:13'), '4732', { subjectUserName: 'admin.mori', memberName: 'WIN-FIN-01\\maint-fin', targetUserName: 'Administrators', targetSid: 'S-1-5-32-544' }, 'Training: member added to local Administrators', 10, ['group_change']),
      windows('approved-admin-removed', iso('2026-10-16', '11:26'), '4733', { subjectUserName: 'admin.mori', memberName: 'WIN-FIN-01\\maint-fin', targetUserName: 'Administrators', targetSid: 'S-1-5-32-544' }, 'Training: member removed from local Administrators', 5, ['group_change'])
    ],
    steps: standardSteps(adminId, 'guided', 'win-fin-01'),
    answer: {
      verdict: 'benign', priority: 'low', action: 'monitor', target: '002',
      evidenceGroups: [['approved-admin-created'], ['approved-admin-added'], ['approved-admin-removed']], documentIds: ['approved-admin-scope', 'approved-admin-change'],
      facts: B('11:12 UTCにadmin.moriがwin-fin-01へmaint-finを作成、11:13にAdministratorsへ追加し、11:26に同グループから削除した。端末・実行者・対象・作業時間がCHG-204と一致する。アカウント削除やソフト更新成功まではこのログで確認していない。', 'admin.mori created maint-fin on win-fin-01 at 11:12 UTC, added it to Administrators at 11:13, and removed the membership at 11:26. The endpoint, actor, target, and time match CHG-204. These records do not establish account deletion or a successful software update.'),
      nextStep: B('CHG-204との照合結果と3件の根拠を作業記録へ残し、継続監視する。時間外の再追加や別アカウントへの追加があれば別件として調査する。', 'Record the CHG-204 comparison and three supporting events, then continue monitoring. Investigate any later re-addition or addition of a different account as a new finding.'),
      explanation: B('管理者追加のlevelは高くても、対象と時間を含む承認内容および戻し操作まで一致しています。アラートが正しい検出であることと、悪意のある事象であることは別です。', 'The administrator-addition event is sensitive, but the full approved scope and removal step match. A correctly detected event is not necessarily malicious activity.')
    }
  });

  const serviceId = 'service-persistence';
  const service = assemble({
    id: serviceId, stage: 'checklist',
    title: B('チェックリスト調査：新しいサービスの確認', 'Checklist: investigate a new service'),
    brief: B('win-fin-01でサービスが新規登録されました。サービス名だけで判断せず、実行パス、起動設定、権限、直前のプロセス記録、承認範囲を確認してください。', 'A new service was registered on win-fin-01. Inspect its executable path, startup setting, account, preceding process record, and approval scope rather than judging its name alone.'),
    objectives: [B('サービス登録と関連プロセスを時系列で突合する', 'Correlate service registration and related process activity'), B('自動起動・実行権限・パスを読み取る', 'Read startup type, execution account, and path'), B('不審な構成とマルウェア確定を区別して引き継ぐ', 'Escalate suspicious configuration without claiming proven malware')],
    timeRange: { from: iso('2026-10-17', '12:00'), to: iso('2026-10-17', '12:40') },
    hints: [
      B('サービス関連のeventIDと端末で絞り込み、登録に使われた実行パスを確認します。', 'Filter by endpoint and service event ID, then inspect the registered executable path.'),
      B('7045はサービス登録、4688はプロセス作成です。data.win.system.eventIDを使い両方を見ます。', 'Event 7045 records service registration; 4688 records process creation. Use data.win.system.eventID to inspect both.'),
      B('12:18のsc.exeによる登録コマンドと12:19のInvoiceUpdater登録が対応します。C:\\ProgramData\\Invoice\\updater.exe、auto start、LocalSystemは作業票の範囲にありません。', 'The sc.exe command at 12:18 corresponds to InvoiceUpdater registration at 12:19. C:\\ProgramData\\Invoice\\updater.exe, auto start, and LocalSystem are outside the approved change.')
    ],
    documents: documents(serviceId,
      B('対象期間は2026-10-17 12:00–12:40 UTC。win-fin-01のSystem 7045とSecurity 4688を選定収集し、4688のコマンドラインも含みます。バイナリ本体、署名検証結果、ネットワーク通信、サービスの実稼働状態はありません。パスやサービス名が不審でもマルウェアの同定には追加調査が必要です。', 'Window: 2026-10-17 12:00–12:40 UTC. Selected win-fin-01 System 7045 and Security 4688 events are available, including 4688 command lines. Binary contents, signature verification, network traffic, and actual service-running status are unavailable. A suspicious name or path alone does not identify malware.'),
      B('作業予定 CHG-207と構成基準', 'Planned change CHG-207 and baseline'),
      B('CHG-207はdb-01のバックアップ設定変更のみを承認しています。win-fin-01の新規サービス導入は予定されていません。fin.userは経理部門の通常業務用アカウントで、運用上のサービス導入担当ではなく、サービス導入の権限利用や作業は承認されていません。ただし、この資料から当時の実効権限や昇格の有無は判断できません。標準インベントリ製品はC:\\Program Files\\OpsInventory\\配下を使用します。InvoiceUpdaterというサービス、ProgramData\\Invoice配下のバイナリ、LocalSystemでの自動起動は当日の承認一覧にありません。業務端末のため、停止や削除は上位担当の確認を経て行います。', 'CHG-207 approves only a backup-configuration change on db-01. No new service installation is scheduled on win-fin-01. fin.user is an ordinary finance-business account, not an operations service installer; neither use of installation privileges nor this installation work is approved for it. This record does not establish the account’s effective privileges or whether elevation occurred at that time. The standard inventory product uses C:\\Program Files\\OpsInventory\\. InvoiceUpdater, a binary under ProgramData\\Invoice, and its automatic LocalSystem startup are absent from today’s approvals. Obtain responder review before stopping or deleting anything on this business endpoint.')),
    events: [
      windows('service-persistence-process', iso('2026-10-17', '12:18'), '4688', { subjectUserName: 'fin.user', newProcessName: 'C:\\Windows\\System32\\sc.exe', commandLine: 'sc.exe create InvoiceUpdater binPath= C:\\ProgramData\\Invoice\\updater.exe start= auto obj= LocalSystem', parentProcessName: 'C:\\Windows\\System32\\cmd.exe' }, 'Training: service-creation command observed', 7, ['process_creation']),
      windows('service-persistence-installed', iso('2026-10-17', '12:19'), '7045', { serviceName: 'InvoiceUpdater', imagePath: 'C:\\ProgramData\\Invoice\\updater.exe', startType: 'auto start', accountName: 'LocalSystem' }, 'Training: new auto-start service registered', 10, ['service_installation'])
    ],
    steps: standardSteps(serviceId, 'checklist', 'win-fin-01'),
    answer: {
      verdict: 'incident', priority: 'high', action: 'escalate', target: '002',
      evidenceGroups: [['service-persistence-process'], ['service-persistence-installed']], documentIds: ['service-persistence-scope', 'service-persistence-change'],
      facts: B('12:18 UTCにwin-fin-01でfin.userによるsc.exeのサービス作成コマンドを観測し、12:19に同名・同パスのInvoiceUpdaterが登録された。ProgramData配下の実行ファイルをLocalSystemで自動起動する設定は承認外。サービスの実行、バイナリの悪性、通信先は未確認。', 'At 12:18 UTC, win-fin-01 recorded a service-creation command by fin.user using sc.exe. At 12:19, InvoiceUpdater was registered with the matching path. Automatic LocalSystem execution from ProgramData is unapproved. Service execution, binary maliciousness, and destinations are unconfirmed.'),
      nextStep: B('上位担当へ高優先度で引き継ぎ、サービス設定とプロセス記録を保全する。端末担当者に作業有無を確認し、バイナリの取得・署名やハッシュ確認・実行状況の調査を依頼する。停止や隔離の判断も依頼する。', 'Escalate at high priority and preserve service configuration and process records. Confirm work with the endpoint owner, request binary collection, signature/hash checks and execution-state investigation, and ask the responder to decide stopping or isolation.'),
      explanation: B('名前の印象ではなく、登録コマンドと結果の一致、自動起動権限、承認外の変更が引継ぎ理由です。この記録だけでは実行済みマルウェアや侵入経路は確定できません。', 'Escalation is based on the matching command and registration, automatic privileged execution, and lack of approval. These records alone do not prove executed malware or the entry route.')
    }
  });

  const gapId = 'collection-gap';
  const gap = assemble({
    id: gapId, stage: 'checklist',
    title: B('チェックリスト調査：ログが来なくなった端末', 'Checklist: an endpoint stopped sending data'),
    brief: B('db-01の監視が途絶えています。「アラートがないから安全」と判断せず、最後の観測、エージェント状態、保守予定を突合し、次の確認先を決めてください。', 'Monitoring from db-01 has stopped. Compare the last observation, agent status, and maintenance window, then choose the next owner to contact. A lack of alerts is not evidence of safety.'),
    objectives: [B('エージェント状態とイベント時刻を突合する', 'Compare agent state with event timestamps'), B('イベントの不在と観測できない状態を区別する', 'Distinguish absence of events from absence of visibility'), B('保守予定を超えた監視欠落の確認依頼を作る', 'Request verification of a collection gap beyond maintenance')],
    timeRange: { from: iso('2026-10-18', '13:00'), to: iso('2026-10-18', '13:40') },
    disconnected: { id: '003', at: iso('2026-10-18', '13:16') },
    hints: [
      B('Endpointsでstatusを確認し、対象端末の「イベントを調べる」からThreat Huntingのイベント一覧へ移動します。状態の絞り込みはWQLの status=disconnected です。', 'Inspect status in Endpoints, then select “Investigate events” for the endpoint to open the Threat Hunting event list. The WQL status filter is status=disconnected.'),
      B('db-01の最後の通常ログと、manager側の切断通知は別の観測です。通知の時刻を端末が動いた時刻と混同しないでください。', 'The last normal db-01 log and the manager-side disconnect notification are different observations. Do not mistake notification time for endpoint activity time.'),
      B('13:15の最終業務ログ、13:16のlastKeepAlive、13:20の切断通知を確認します。保守は13:30までの予定ですが、13:40時点で復旧を確認できません。「判断保留」／「中」／「追加確認を依頼」が適切です。', 'Check the last business log at 13:15, lastKeepAlive at 13:16, and notification at 13:20. Maintenance should end by 13:30, but recovery is unconfirmed at 13:40. Select “Insufficient evidence” / “Medium” / “Request verification”.')
    ],
    documents: documents(gapId,
      B('対象期間は2026-10-18 13:00–13:40 UTC。db-01は13:15まで定期処理の選定ログがあり、lastKeepAliveは13:16です。13:20の切断イベントはmanager側の状態を教材用ヘルスコレクターが記録したものです。agentは監視対象db-01を示し、13:20にdb-01自身が送信したログではありません。Endpoints画面の状態は13:40時点のスナップショットです。切断後の端末上の行動は観測できません。', 'Window: 2026-10-18 13:00–13:40 UTC. Selected routine db-01 logs end at 13:15; lastKeepAlive is 13:16. The 13:20 disconnect event is a manager-side state recorded by a training health collector. Its agent identifies monitored db-01; it is not a log sent by db-01 at 13:20. Endpoints shows a snapshot at 13:40. Endpoint activity after the collection gap is not visible.'),
      B('ネットワーク保守票 CHG-209', 'Network maintenance CHG-209'),
      B('db-01の接続セグメントを13:15–13:30 UTCに保守します。一時的な監視断は想定内ですが、終了時にエージェント再接続を確認する手順です。13:40時点で完了連絡・復旧確認は未着です。ネットワーク担当へ保守完了、端末担当へエージェントサービス状態を確認してください。保守が原因と断定したり、攻撃による停止と断定したりできる資料はありません。', 'The db-01 network segment is under maintenance from 13:15 to 13:30 UTC. A temporary monitoring gap is expected, but agent reconnection must be checked afterward. At 13:40, neither completion notice nor recovery confirmation has arrived. Ask the network owner about completion and the endpoint owner about the agent service. Available records do not prove maintenance or an attack caused the disconnection.')),
    events: [
      event('collection-gap-last', iso('2026-10-18', '13:15'), '003', 100001, 3, 'Training: scheduled job completed', ['wazuhroom', 'scheduled_task'], 'wazuhroom-scheduler', { service: 'database-backup', action: 'job_completed', status: 'completed' }, '2026-10-18T13:15:00Z db-01 room-scheduler: job=database-backup result=completed'),
      event('collection-gap-disconnected', iso('2026-10-18', '13:20'), '003', 100030, 7, 'Training: manager observed agent disconnection', ['wazuhroom', 'agent_status'], 'wazuhroom-agent-health', { status: 'disconnected', lastKeepAlive: iso('2026-10-18', '13:16') }, '2026-10-18T13:20:00Z manager room-health-collector: agent_id=003 agent_name=db-01 status=disconnected lastKeepAlive=2026-10-18T13:16:00.000Z')
    ],
    steps: standardSteps(gapId, 'checklist', 'db-01'),
    answer: {
      verdict: 'unknown', priority: 'medium', action: 'verify', target: '003',
      evidenceGroups: [['collection-gap-last'], ['collection-gap-disconnected']], documentIds: ['collection-gap-scope', 'collection-gap-change'],
      facts: B('db-01の最後の通常ログは13:15 UTC、lastKeepAliveは13:16。managerは13:20に切断を観測し、13:40の状態もdisconnected。13:15–13:30の保守予定はあるが復旧は未確認。欠落期間の端末動作も切断原因も判断できない。', 'The last normal db-01 log is at 13:15 UTC; lastKeepAlive is 13:16. The manager observed disconnection at 13:20, and the 13:40 snapshot still shows disconnected. Maintenance was planned for 13:15–13:30, but recovery is unconfirmed. Endpoint activity during the gap and the cause remain unknown.'),
      nextStep: B('ネットワーク担当に保守完了と経路復旧、端末担当にエージェント稼働・送信状態を確認する。再接続時刻と欠落範囲を記録し、復旧後に遅延ログや追加の異常を確認する。', 'Ask the network owner to verify maintenance completion and connectivity, and the endpoint owner to check agent operation and delivery. Record the reconnection time and gap, then inspect delayed logs or further anomalies after recovery.'),
      explanation: B('監視対象の状態を把握できないため「判断保留」です。予定保守は候補となる説明ですが、予定時間を過ぎても復旧を確認できないので、優先度「中」で「追加確認を依頼」を選びます。ログがないことを正常と扱わないのが要点です。', 'Select “Insufficient evidence” because endpoint visibility is missing. Scheduled maintenance is a possible explanation, but unconfirmed recovery beyond its window warrants “Medium” priority and “Request verification”. Missing telemetry must not be treated as normal activity.')
    }
  });

  const mixedId = 'mixed-auth';
  const mixed = assemble({
    id: mixedId, stage: 'independent',
    title: B('自力調査：同じ時刻の別々の出来事', 'Independent: simultaneous but separate activity'),
    brief: B('web-01の認証失敗と、win-fin-01のサービス導入が同じ時間帯に見つかりました。主な報告対象はwin-fin-01の導入です。win-fin-01のログオン・サービス登録に加え、比較に用いたweb-01の認証失敗も少なくとも1件、証拠に含めてください。「承認済み導入 CHG-212」と「承認済み認証テスト EX-12」を読み、両者を同じ攻撃と結びつける根拠があるかを確認して報告します。', 'SSH failures on web-01 and a service installation on win-fin-01 occurred in the same window. Your primary reporting target is the win-fin-01 installation. Include its logon and service registration plus at least one web-01 authentication failure used for comparison as evidence. Read “Approved deployment CHG-212” and “Approved authentication test EX-12”, then report whether evidence links the two as one attack.'),
    objectives: [B('複数端末を行き来して必要な証拠を選ぶ', 'Move across endpoints and select relevant evidence'), B('時間の一致だけで因果関係を断定しない', 'Avoid inferring causation from time overlap alone'), B('承認範囲とログを独力で照合して報告する', 'Independently compare logs with approvals and report')],
    timeRange: { from: iso('2026-10-19', '14:00'), to: iso('2026-10-19', '14:40') },
    hints: [
      B('まず報告対象と、比較対象の出来事を分けて整理しましょう。結びつけるには時刻以外の一致が必要です。', 'Separate the assigned finding from the activity you are comparing. A connection needs evidence beyond overlapping time.'),
      B('win-fin-01の接続元・利用者・サービスのパスを作業票と照合し、その後web-01の失敗の接続元を確認します。', 'Compare the win-fin-01 source, account, and service path with the change, then inspect the source of the web-01 failures.'),
      B('14:11のadmin.itoのログオン、14:14のOpsInventory登録、web-01のscancheck失敗を選びます。「承認済み導入 CHG-212」と「承認済み認証テスト EX-12」でそれぞれ説明でき、同一攻撃を示す証拠はありません。', 'Select admin.ito’s 14:11 logon, the 14:14 OpsInventory registration, and a web-01 scancheck failure. “Approved deployment CHG-212” and “Approved authentication test EX-12” respectively explain them; no evidence establishes a shared attack.')
    ],
    documents: documents(mixedId,
      B('対象期間は2026-10-19 14:00–14:40 UTC。web-01のSSH認証とwin-fin-01のSecurity 4624/System 7045を選定収集しています。4624のlogonType 10はこの教材ではリモート対話ログオンです。7045にはサービス実行アカウントはありますが登録操作を行った人物は記録されていません。直前のログオンと登録を同一人物の操作と確定する接続IDはありません。', 'Window: 2026-10-19 14:00–14:40 UTC. Selected web-01 SSH authentication and win-fin-01 Security 4624/System 7045 events are collected. In this case, logonType 10 represents remote interactive logon. 7045 records the service account but not the person who registered it. There is no session identifier proving that the preceding logon and registration share an actor.'),
      B('承認済み導入 CHG-212', 'Approved deployment CHG-212'),
      B('対象：win-fin-01。時間：14:10–14:25 UTC。担当：admin.ito、踏み台10.20.0.8。OpsInventoryをC:\\Program Files\\OpsInventory\\agent.exeからLocalSystemで自動起動する構成を承認済みです。このケースの導入は上記条件と照合し、別端末のアラートは別途根拠を確認します。承認はバイナリの完全性や将来のすべての動作を保証するものではありません。', 'Endpoint: win-fin-01. Window: 14:10–14:25 UTC. Operator: admin.ito through jump host 10.20.0.8. OpsInventory is approved to start automatically as LocalSystem from C:\\Program Files\\OpsInventory\\agent.exe. Compare this installation with those conditions; separately establish the basis of findings on other endpoints. Approval does not guarantee binary integrity or all future activity.'),
      [document('mixed-auth-exercise', B('承認済み認証テスト EX-12', 'Approved authentication test EX-12'), B('14:00–14:30 UTCにweb-01だけを対象に、203.0.113.99からscancheckへの失敗認証を送る試験を承認しています。試験はログオン成功を目的とせず、Windows端末へのサービス導入も含みません。予定外の成功、別ユーザー、別端末を見つけたら試験担当に確認してください。', 'EX-12 approves failed authentication attempts for scancheck on web-01 only, from 203.0.113.99 between 14:00 and 14:30 UTC. It does not authorize successful access or service installation on Windows endpoints. Confirm unexpected successes, other accounts, or other endpoints with the test owner.'))]),
    events: [
      ssh('mixed-auth-failure-1', iso('2026-10-19', '14:10'), '001', false, 'scancheck', '203.0.113.99', 45001),
      ssh('mixed-auth-failure-2', iso('2026-10-19', '14:12'), '001', false, 'scancheck', '203.0.113.99', 45002),
      ssh('mixed-auth-failure-3', iso('2026-10-19', '14:14'), '001', false, 'scancheck', '203.0.113.99', 45003),
      windows('mixed-auth-logon', iso('2026-10-19', '14:11'), '4624', { targetUserName: 'admin.ito', ipAddress: '10.20.0.8', logonType: 10 }, 'Training: Windows authentication succeeded', 3, ['authentication_success']),
      windows('mixed-auth-service', iso('2026-10-19', '14:14'), '7045', { serviceName: 'OpsInventory', imagePath: 'C:\\Program Files\\OpsInventory\\agent.exe', startType: 'auto start', accountName: 'LocalSystem' }, 'Training: new auto-start service registered', 10, ['service_installation'])
    ],
    steps: standardSteps(mixedId, 'independent', 'win-fin-01 / web-01'),
    answer: {
      verdict: 'benign', priority: 'low', action: 'monitor', target: '002',
      evidenceGroups: [['mixed-auth-logon'], ['mixed-auth-service'], ['mixed-auth-failure-1', 'mixed-auth-failure-2', 'mixed-auth-failure-3']], documentIds: ['mixed-auth-scope', 'mixed-auth-change', 'mixed-auth-exercise'],
      facts: B('win-fin-01では14:11 UTCにadmin.itoが10.20.0.8からログオンし、14:14に承認されたパス・権限・起動設定でOpsInventoryが登録された。CHG-212の範囲と一致する。web-01の203.0.113.99からscancheckへの失敗はEX-12の範囲内。時間の重なり以外に同一攻撃を示す証拠はなく、7045の登録実行者やバイナリの完全性は未確認。', 'On win-fin-01, admin.ito logged on from 10.20.0.8 at 14:11 UTC; OpsInventory was registered at 14:14 with the approved path, account, and startup settings, matching CHG-212. Failures for scancheck from 203.0.113.99 on web-01 fit EX-12. No evidence beyond time overlap links a common attack. The 7045 registration actor and binary integrity remain unconfirmed.'),
      nextStep: B('win-fin-01の導入を承認作業と一致する事象として記録し継続監視する。比較したSSH失敗とEX-12も記録し、予定外の成功や対象拡大が出たら試験担当へ確認する。', 'Record the win-fin-01 installation as consistent with approved work and continue monitoring. Retain the compared SSH failures and EX-12; contact the test owner if unplanned successes or expanded targets appear.'),
      explanation: B('別端末・別接続元のアラートが同じ時間に出ても、同じ攻撃とは限りません。両方の承認範囲と記録を確認できることが、根拠のある正常判断につながります。承認があるだけで将来の安全まで保証しない点も残します。', 'Overlapping alerts on different endpoints and sources do not necessarily form one attack. Comparing each observation with its own approval supports a reasoned benign verdict without guaranteeing future safety.')
    }
  });

  const fimId = 'fim-change';
  const hashA = '1a'.repeat(32);
  const hashB = '2b'.repeat(32);
  const hashC = '3c'.repeat(32);
  const hashD = '4d'.repeat(32);
  const fim = assemble({
    id: fimId, stage: 'independent',
    title: B('自力調査：変更されたファイルと承認の境界', 'Independent: file changes and approval boundaries'),
    brief: B('web-01のファイル変更が通知されました。同じ時間の承認済み作業を見つけても、それですべてを説明できるとは限りません。FIMと認証・コマンド記録を行き来し、重要設定の変更について一次報告してください。', 'File changes were reported on web-01. Approved work in the same window may not explain every change. Move between FIM and authentication/command records and report on the critical configuration change.'),
    objectives: [B('FIMのパス・変更種別・前後のハッシュを読む', 'Read FIM paths, change type, and before/after hashes'), B('FIMから同じ端末の関連イベントへ調査を広げる', 'Pivot from FIM to related events on the same endpoint'), B('観測された変更と未確認の内容・影響を区別する', 'Separate observed changes from unverified content and impact')],
    timeRange: { from: iso('2026-10-20', '15:00'), to: iso('2026-10-20', '15:40') },
    hints: [
      B('FIMで変更されたパスを作業票の対象と照合してください。端末と時間が合うだけでは承認と一致したことになりません。', 'Compare each changed path in FIM with the ticket. Matching endpoint and time alone does not establish approval.'),
      B('syscheck.path: "/etc/ssh/sshd_config" を確認し、Threat Huntingのイベント一覧で同じweb-01の前後のログを調べます。', 'Inspect syscheck.path: "/etc/ssh/sshd_config", then investigate surrounding web-01 activity in the Threat Hunting event list.'),
      B('15:12のcpコマンド、15:13のsshd_config変更、15:14の承認対象index.html変更を証拠にします。変更前後のハッシュは内容変化を示しますが、設定値や変更による侵入可否は示しません。', 'Select the cp command at 15:12, sshd_config change at 15:13, and approved index.html change at 15:14. Different hashes indicate content change, but not the resulting settings or exploitability.')
    ],
    documents: documents(fimId,
      B('対象期間は2026-10-20 15:00–15:40 UTC。web-01の/etc/ssh/sshd_configと/var/www/html/index.htmlをFIM監視しています。syscheck.pathは変更対象、eventは変更種別、sha256_before/afterは前後の内容ハッシュです。内容差分・whodata・変更プロセスIDはありません。sudo記録は別ソースで、FIMの変更者を確定する接続IDもありません。ハッシュ値は教材用です。', 'Window: 2026-10-20 15:00–15:40 UTC. FIM monitors /etc/ssh/sshd_config and /var/www/html/index.html on web-01. syscheck.path identifies the file, event the change type, and sha256_before/after its content hashes. Content diffs, whodata, and modifying process IDs are unavailable. sudo records are a separate source and cannot conclusively attribute a FIM change. Hashes are training values.'),
      B('Web更新作業票 CHG-215', 'Website update CHG-215'),
      B('対象：web-01。時間：15:10–15:20 UTC。担当：ops.kai。許可対象は/var/www/html/index.htmlの文面更新のみです。SSHなど認証設定の変更、デーモン再起動は承認に含まれません。重要な認証設定の承認外変更は上位担当へ引き継ぎ、設定内容・業務影響・戻し手順を確認してから対処してください。', 'Endpoint: web-01. Window: 15:10–15:20 UTC. Operator: ops.kai. Only text changes to /var/www/html/index.html are approved. Authentication configuration changes such as SSH settings and daemon restarts are excluded. Escalate unapproved critical authentication changes and verify content, business impact, and rollback procedure before acting.')),
    events: [
      ssh('fim-change-logon', iso('2026-10-20', '15:10'), '001', true, 'ops.kai', '10.20.0.8', 46001),
      event('fim-change-command', iso('2026-10-20', '15:12'), '001', 100013, 7, 'Training: privileged configuration-copy command', ['wazuhroom', 'sudo', 'configuration_change'], 'wazuhroom-sudo', { srcuser: 'ops.kai', dstuser: 'root', action: 'privileged_command', command: '/usr/bin/cp /tmp/sshd_config.new /etc/ssh/sshd_config' }, '2026-10-20T15:12:00Z web-01 sudo: ops.kai : TTY=pts/1 ; PWD=/home/ops.kai ; USER=root ; COMMAND=/usr/bin/cp /tmp/sshd_config.new /etc/ssh/sshd_config'),
      event('fim-change-config', iso('2026-10-20', '15:13'), '001', 100040, 7, 'Training: monitored file content changed', ['wazuhroom', 'syscheck', 'syscheck_entry_modified'], 'wazuhroom-fim', { action: 'modified', path: '/etc/ssh/sshd_config' }, `File '/etc/ssh/sshd_config' modified. SHA256 before: ${hashA}. SHA256 after: ${hashB}.`, { syscheck: { path: '/etc/ssh/sshd_config', event: 'modified', sha256_before: hashA, sha256_after: hashB } }),
      event('fim-change-web', iso('2026-10-20', '15:14'), '001', 100040, 7, 'Training: monitored file content changed', ['wazuhroom', 'syscheck', 'syscheck_entry_modified'], 'wazuhroom-fim', { action: 'modified', path: '/var/www/html/index.html' }, `File '/var/www/html/index.html' modified. SHA256 before: ${hashC}. SHA256 after: ${hashD}.`, { syscheck: { path: '/var/www/html/index.html', event: 'modified', sha256_before: hashC, sha256_after: hashD } })
    ],
    steps: standardSteps(fimId, 'independent', 'web-01'),
    answer: {
      verdict: 'incident', priority: 'high', action: 'escalate', target: '001',
      evidenceGroups: [['fim-change-command'], ['fim-change-config'], ['fim-change-web']], documentIds: ['fim-change-scope', 'fim-change-change'],
      facts: B('15:12 UTCにops.kaiによるsshd_configへのcpコマンド、15:13に同ファイルの内容ハッシュ変更をweb-01で観測した。15:14のindex.html変更はCHG-215の対象だが、SSH設定は範囲外。FIMに変更者・内容差分がなく、設定値、反映状態、実行人物、影響は未確認。', 'web-01 recorded a cp command by ops.kai targeting sshd_config at 15:12 UTC and a content-hash change for that file at 15:13. The index.html change at 15:14 is in CHG-215 scope; SSH configuration is not. FIM lacks actor and content-diff information. Settings, activation state, person, and impact remain unconfirmed.'),
      nextStep: B('認証設定の承認外変更として上位担当へ高優先度で引き継ぎ、FIM・sudo・承認記録を保全する。ops.kai担当者へ実施確認を行い、前後の設定差分と設定反映状況、適切な戻し方を確認してもらう。', 'Escalate the unapproved authentication-configuration change at high priority and preserve FIM, sudo, and approval records. Ask the ops.kai owner to confirm the activity and request a configuration diff, activation check, and appropriate rollback plan.'),
      explanation: B('同じ時間に承認作業があっても、承認されたファイルはindex.htmlだけです。FIMは「何が変わったか」を調査する入口であり、差分のないハッシュから設定内容や悪意を推測しません。', 'The approved work in this window covers only index.html. FIM provides a lead about what changed; hashes without a content diff cannot establish settings or intent.')
    }
  });

  const cases = [tutorial, auth, admin, service, gap, mixed, fim];
  return { version: 'wazuhroom-1', referenceVersion: '4.14', cases, agents: copy(tutorial.agents) };
}));
