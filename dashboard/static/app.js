(() => {
    const toast = document.getElementById("toast");
    const toastMessage = document.getElementById("toast-message");

    const showToast = (message) => {
        if (!toast || !toastMessage) return;
        toastMessage.textContent = message;
        toast.classList.remove("hidden");
        setTimeout(() => toast.classList.add("hidden"), 3000);
    };

    const initUploadCards = () => {
        const cards = document.querySelectorAll("[data-upload-card]");
        cards.forEach((card) => {
            const input = card.querySelector(".file-input");
            const fileName = card.querySelector(".file-name");
            const statusDot = card.querySelector(".status-dot");

            const updateStatus = (file) => {
                if (!file) return;
                fileName.textContent = file.name;
                statusDot.classList.remove("bg-muted");
                statusDot.classList.add("bg-low");
            };

            input.addEventListener("change", (event) => {
                updateStatus(event.target.files[0]);
            });

            card.addEventListener("dragover", (event) => {
                event.preventDefault();
                card.classList.add("border-[#3b475a]");
            });
            card.addEventListener("dragleave", () => {
                card.classList.remove("border-[#3b475a]");
            });
            card.addEventListener("drop", (event) => {
                event.preventDefault();
                card.classList.remove("border-[#3b475a]");
                const file = event.dataTransfer.files[0];
                if (file) {
                    input.files = event.dataTransfer.files;
                    updateStatus(file);
                }
            });
        });
    };

    const initScanForm = () => {
        const form = document.getElementById("scan-form");
        const runButton = document.getElementById("run-scan");
        const status = document.getElementById("scan-status");
        if (!form || !runButton || !status) return;

        form.addEventListener("submit", () => {
            runButton.disabled = true;
            runButton.classList.add("opacity-60", "cursor-not-allowed");
            status.classList.remove("hidden");
            status.classList.add("flex");
            showToast("Scan initiated. Analyzing configurations.");
        });

        form.addEventListener("reset", () => {
            document.querySelectorAll("[data-upload-card]").forEach((card) => {
                const fileName = card.querySelector(".file-name");
                const statusDot = card.querySelector(".status-dot");
                if (fileName) fileName.textContent = "No file selected";
                if (statusDot) {
                    statusDot.classList.remove("bg-low");
                    statusDot.classList.add("bg-muted");
                }
            });
        });
    };

    const initRiskChart = () => {
        const chartEl = document.getElementById("riskChart");
        if (!chartEl || typeof Chart === "undefined") return;
        // Chart.js used for compact risk distribution without heavy visualization overhead.
        const data = {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [
                    parseInt(chartEl.dataset.critical || "0", 10),
                    parseInt(chartEl.dataset.high || "0", 10),
                    parseInt(chartEl.dataset.medium || "0", 10),
                    parseInt(chartEl.dataset.low || "0", 10)
                ],
                backgroundColor: ["#dc2626", "#f97316", "#eab308", "#22c55e"],
                borderRadius: 6
            }]
        };
        new Chart(chartEl, {
            type: "bar",
            data,
            options: {
                plugins: { legend: { display: false } },
                scales: {
                    y: { ticks: { color: "#9ca3af" }, grid: { color: "#1f2933" } },
                    x: { ticks: { color: "#9ca3af" }, grid: { display: false } }
                }
            }
        });
    };

    const initHeatmap = () => {
        const cells = document.querySelectorAll(".heat-cell");
        if (!cells.length) return;
        // Heatmap stays as a DOM grid to keep a SIEM-style dense layout with fast hover tooltips.
        const tooltip = document.createElement("div");
        tooltip.className = "absolute z-50 hidden px-3 py-2 text-xs rounded-lg border border-border bg-[#0b1220] text-ink mono";
        document.body.appendChild(tooltip);

        const colorMap = {
            Critical: "rgba(220, 38, 38, 0.35)",
            High: "rgba(249, 115, 22, 0.3)",
            Medium: "rgba(234, 179, 8, 0.25)",
            Low: "rgba(34, 197, 94, 0.2)"
        };

        cells.forEach((cell) => {
            const risk = cell.dataset.risk || "Low";
            cell.style.background = colorMap[risk] || "rgba(148, 163, 184, 0.12)";

            cell.addEventListener("mouseenter", (event) => {
                tooltip.innerHTML = `
                    <div class="text-ink font-semibold">${risk} Risk</div>
                    <div class="text-muted">Impact: ${cell.dataset.impact} | Likelihood: ${cell.dataset.likelihood}</div>
                    <div class="text-muted">Example: ${cell.dataset.example}</div>
                    <div class="text-muted">Findings: ${cell.dataset.count}</div>
                `;
                tooltip.classList.remove("hidden");
                const rect = event.target.getBoundingClientRect();
                tooltip.style.left = `${rect.left + window.scrollX + 12}px`;
                tooltip.style.top = `${rect.top + window.scrollY - 10}px`;
            });
            cell.addEventListener("mouseleave", () => {
                tooltip.classList.add("hidden");
            });
        });
    };

    const initExpandableRows = () => {
        const buttons = document.querySelectorAll(".toggle-row");
        buttons.forEach((button) => {
            button.addEventListener("click", () => {
                const target = document.getElementById(button.dataset.target);
                if (!target) return;
                target.classList.toggle("hidden");
                button.textContent = target.classList.contains("hidden") ? "View" : "Hide";
            });
        });
    };

    const initPage = () => {
        initUploadCards();
        initScanForm();
        initRiskChart();
        initHeatmap();
        initExpandableRows();

        if (document.body.dataset.page === "results") {
            showToast("Scan completed. Review prioritized findings.");
        }
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initPage);
    } else {
        initPage();
    }
})();
