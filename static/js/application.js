/**
 * AI IDS Dashboard — real-time UI (Socket.IO namespace /test unchanged)
 */
(function ($) {
  "use strict";

  var MAX_ROWS = 10;
  var messages_received = [];
  var totalFlowsSeen = 0;
  var attacksCount = 0;
  var suspiciousSrcIps = {};
  var lastAttackSoundTime = 0;
  var SOUND_COOLDOWN_MS = 1800;

  var chartColors = {
    fill: "rgba(34, 211, 238, 0.35)",
    border: "rgba(34, 211, 238, 0.95)",
    grid: "rgba(51, 65, 85, 0.6)",
    text: "#94a3b8",
  };

  function stripTags(html) {
    var tmp = document.createElement("div");
    tmp.innerHTML = html;
    return (tmp.textContent || tmp.innerText || "").trim();
  }

  function normalizePred(p) {
    return String(p)
      .replace(/^['"]|['"]$/g, "")
      .trim();
  }

  function isBenignPrediction(pred) {
    return normalizePred(pred).toLowerCase() === "benign";
  }

  function parseRiskTier(riskHtml) {
    var t = stripTags(riskHtml).toLowerCase();
    if (t.indexOf("very high") !== -1) return { key: "VERY HIGH", level: 4 };
    if (t.indexOf("high") !== -1 && t.indexOf("very") === -1) return { key: "HIGH", level: 3 };
    if (t.indexOf("medium") !== -1) return { key: "MEDIUM", level: 2 };
    if (t.indexOf("low") !== -1 && t.indexOf("minimal") === -1) return { key: "LOW", level: 1 };
    if (t.indexOf("minimal") !== -1) return { key: "MINIMAL", level: 0 };
    return { key: "—", level: -1 };
  }

  function riskIconHtml(riskHtml) {
    var tier = parseRiskTier(riskHtml).key;
    if (tier === "VERY HIGH" || tier === "HIGH")
      return '<span class="risk-icon" title="' + tier + '">🔴 ' + tier + "</span>";
    if (tier === "MEDIUM")
      return '<span class="risk-icon" title="' + tier + '">🟡 ' + tier + "</span>";
    if (tier === "LOW" || tier === "MINIMAL")
      return '<span class="risk-icon" title="' + tier + '">🟢 ' + tier + "</span>";
    return '<span class="risk-icon">⚪ ' + tier + "</span>";
  }

  function playAttackBeep() {
    var now = Date.now();
    if (now - lastAttackSoundTime < SOUND_COOLDOWN_MS) return;
    lastAttackSoundTime = now;
    try {
      var ctx = new (window.AudioContext || window.webkitAudioContext)();
      var o = ctx.createOscillator();
      var g = ctx.createGain();
      o.type = "square";
      o.frequency.value = 880;
      g.gain.setValueAtTime(0.08, ctx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
      o.connect(g);
      g.connect(ctx.destination);
      o.start(ctx.currentTime);
      o.stop(ctx.currentTime + 0.16);
    } catch (e) {
      /* ignore */
    }
  }

  function animateNumber($el, to, duration) {
    var from = parseInt($el.text().replace(/\D/g, ""), 10) || 0;
    if (from === to) {
      $el.text(to);
      return;
    }
    var start = null;
    function step(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / duration, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      $el.text(Math.round(from + (to - from) * eased));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function appendTerminalLine(text, isAttack) {
    var $term = $("#live-terminal");
    var time = new Date().toLocaleTimeString("en-GB", { hour12: false });
    var $p = $("<p/>")
      .addClass("terminal-line")
      .append($("<time/>").text("[" + time + "] "))
      .append(document.createTextNode(text));
    if (isAttack) $p.addClass("terminal-line--attack");
    $term.append($p);
    while ($term.children().length > 200) {
      $term.children().first().remove();
    }
    $term.scrollTop($term[0].scrollHeight);
  }

  function updateHighRiskBanner(tier, flowId, prediction) {
    var $bar = $("#alert-high-risk");
    if (tier.level >= 3) {
      $bar.addClass("is-visible");
      $("#alert-high-risk-msg").text(
        " · Flow #" + flowId + " · " + String(prediction).replace(/['"]/g, "")
      );
    } else {
      $bar.removeClass("is-visible");
    }
  }

  function renderTopIps(ips) {
    var $ul = $("#top-ips-list");
    $ul.empty();
    if (!ips || !ips.length) {
      $ul.append(
        $("<li/>")
          .addClass("empty-state")
          .css({
            padding: "1rem",
            fontSize: "0.75rem",
            color: "var(--text-muted)",
            border: "none",
            background: "transparent",
          })
          .text("No IP statistics yet.")
      );
      return;
    }
    var sorted = ips.slice().sort(function (a, b) {
      return (b.count || 0) - (a.count || 0);
    });
    sorted.slice(0, 12).forEach(function (row) {
      var ip = row.SourceIP;
      var count = row.count;
      var plain = String(ip);
      var isSuspicious = suspiciousSrcIps[plain] > 0;
      var $li = $("<li/>");
      if (isSuspicious) $li.addClass("is-suspicious");
      $li.append(
        $("<span/>").addClass("ip-label").text(plain),
        $("<span/>").addClass("ip-count").text(count)
      );
      $ul.append($li);
    });
  }

  function renderTable() {
    var $tbody = $("#flows-tbody");
    $tbody.empty();
    for (var i = messages_received.length - 1; i >= 0; i--) {
      var row = messages_received[i];
      var prediction = row[10];
      var riskHtml = row[12];
      var attack = !isBenignPrediction(prediction);
      var $tr = $("<tr/>");
      if (attack) $tr.addClass("row-attack");

      for (var j = 0; j < row.length; j++) {
        var cell = row[j];
        var $td = $("<td/>");
        if (j === 12) {
          $td.addClass("risk-cell").html(riskIconHtml(riskHtml) + " " + String(cell));
        } else {
          $td.html(cell != null ? String(cell) : "");
        }
        $tr.append($td);
      }

      var flowId = row[0].toString();
      var $tdAct = $("<td/>");
      var $a = $("<a/>")
        .attr("href", "/flow-detail?flow_id=" + flowId)
        .addClass("btn-detail")
        .text("Detail");
      $tdAct.append($a);
      $tr.append($tdAct);
      $tbody.append($tr);
    }
  }

  function updateMetrics(msg) {
    var row = msg.result;
    var flowId = row[0];
    var prediction = row[10];
    var riskHtml = row[12];
    var attack = !isBenignPrediction(prediction);

    totalFlowsSeen = Math.max(totalFlowsSeen, Number(flowId) || 0);
    if (attack) attacksCount += 1;

    var srcPlain = stripTags(row[1].toString());
    if (attack && srcPlain) {
      suspiciousSrcIps[srcPlain] = (suspiciousSrcIps[srcPlain] || 0) + 1;
    }

    animateNumber($("#metric-total-flows"), totalFlowsSeen, 400);
    animateNumber($("#metric-attacks"), attacksCount, 400);

    var tier = parseRiskTier(riskHtml);
    $("#metric-risk").text(tier.key);

    var ipLen = msg.ips && msg.ips.length ? msg.ips.length : 0;
    animateNumber($("#metric-connections"), ipLen, 350);

    updateHighRiskBanner(tier, flowId, prediction);

    if (attack) {
      playAttackBeep();
      appendTerminalLine(
        "⚠ ATTACK · Flow #" +
          flowId +
          " · class=" +
          normalizePred(prediction) +
          " · src=" +
          srcPlain,
        true
      );
    } else {
      appendTerminalLine(
        "FLOW #" +
          flowId +
          " · benign · " +
          srcPlain +
          " → " +
          stripTags(row[3].toString()),
        false
      );
    }
  }

  function updateChart(myChart, ips) {
    if (!ips || !ips.length) return;
    var labels = [];
    var data = [];
    for (var i = 0; i < ips.length; i++) {
      labels.push(ips[i].SourceIP);
      data.push(ips[i].count);
    }
    myChart.data.labels = labels;
    myChart.data.datasets[0].data = data;
    myChart.data.datasets[0].backgroundColor = labels.map(function () {
      return chartColors.fill;
    });
    myChart.data.datasets[0].borderColor = labels.map(function () {
      return chartColors.border;
    });
    myChart.update();
  }

  $(document).ready(function () {
    var ctx = document.getElementById("trafficChart");
    if (!ctx) return;

    $("#connection-endpoint").text("/test");

    var myChart = new Chart(ctx.getContext("2d"), {
      type: "bar",
      data: {
        labels: [],
        datasets: [
          {
            label: "Flows",
            data: [],
            backgroundColor: [],
            borderColor: [],
            borderWidth: 1,
          },
        ],
      },
      options: {
        legend: { display: false },
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          xAxes: [
            {
              ticks: {
                fontColor: chartColors.text,
                fontFamily: "'JetBrains Mono', monospace",
                maxRotation: 45,
                minRotation: 45,
                fontSize: 9,
              },
              gridLines: { color: chartColors.grid, zeroLineColor: chartColors.grid },
            },
          ],
          yAxes: [
            {
              ticks: {
                beginAtZero: true,
                fontColor: chartColors.text,
                fontFamily: "'JetBrains Mono', monospace",
              },
              gridLines: { color: chartColors.grid, zeroLineColor: chartColors.grid },
            },
          ],
        },
      },
    });

    var socket = io.connect(
      "http://" + document.domain + ":" + location.port + "/test"
    );

    $("#connection-status").text("CONNECTING…");

    socket.on("connect", function () {
      $("#connection-status").text("CONNECTED");
      $("#capture-dot").attr("class", "status-pill__dot");
      appendTerminalLine("SOCKET.IO channel established · listening for flows", false);
    });

    socket.on("disconnect", function () {
      $("#connection-status").text("DISCONNECTED");
      $("#capture-dot").attr("class", "status-pill__dot status-pill__dot--off");
      appendTerminalLine("⚠ Socket disconnected — reconnecting…", true);
    });

    socket.on("connect_error", function () {
      $("#connection-status").text("ERROR");
      $("#capture-dot").attr("class", "status-pill__dot status-pill__dot--warn");
    });

    var loadingHidden = false;
    function hideLoading() {
      if (loadingHidden) return;
      loadingHidden = true;
      $("#dashboard-loading").addClass("is-hidden");
    }

    setTimeout(hideLoading, 4500);

    socket.on("newresult", function (msg) {
      hideLoading();
      console.log("Received result", msg.result);

      if (messages_received.length >= MAX_ROWS) {
        messages_received.shift();
      }
      messages_received.push(msg.result);

      updateMetrics(msg);
      renderTable();
      renderTopIps(msg.ips || []);
      updateChart(myChart, msg.ips || []);
    });
  });
})(jQuery);
