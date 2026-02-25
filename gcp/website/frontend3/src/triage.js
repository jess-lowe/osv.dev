import "./triage.scss";
import "@material/web/textfield/filled-text-field.js";
import "@material/web/button/filled-button.js";
import "@material/web/progress/circular-progress.js";

document.addEventListener("DOMContentLoaded", () => {
  const vulnIdInput = document.getElementById("vuln-id-input");
  const loadBtn = document.getElementById("load-btn");
  const columns = document.querySelectorAll(".triage-column");

  // Map selection values to their respective endpoints/paths
  const sourceConfigMap = {
    // External APIs
    "cve-org": {
      urlTemplate: "https://cveawg.cve.org/api/cve/{id}",
      useProxy: true,
    },
    "nvd-api": {
      urlTemplate: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}",
      useProxy: true,
    },
    // Test Instance
    "test-nvd": {
      bucket: "osv-test-cve-osv-conversion",
      pathTemplate: "nvd-osv/{id}.json",
    },
    "test-cve5": {
      bucket: "osv-test-cve-osv-conversion",
      pathTemplate: "cve5/{id}.json",
    },
    "test-osv": {
      bucket: "osv-test-cve-osv-conversion",
      pathTemplate: "osv-output/{id}.json",
    },
    "test-nvd-metrics": {
      bucket: "osv-test-cve-osv-conversion",
      pathTemplate: "nvd-osv/{id}.metrics.json",
    },
    "test-cve5-metrics": {
      bucket: "osv-test-cve-osv-conversion",
      pathTemplate: "cve5/{id}.metrics.json",
    },
    // Prod Instance
    "prod-nvd": {
      bucket: "cve-osv-conversion",
      pathTemplate: "nvd-osv/{id}.json",
    },
    "prod-cve5": {
      bucket: "cve-osv-conversion",
      pathTemplate: "cve5/{id}.json",
    },
    "prod-osv": {
      bucket: "cve-osv-conversion",
      pathTemplate: "osv-output/{id}.json",
    },
    "prod-nvd-metrics": {
      bucket: "cve-osv-conversion",
      pathTemplate: "nvd-osv/{id}.metrics.json",
    },
    "prod-cve5-metrics": {
      bucket: "cve-osv-conversion",
      pathTemplate: "cve5/{id}.metrics.json",
    },
    // API
    "api-test": {
      urlTemplate: "https://api.test.osv.dev/v1/vulns/{id}",
    },
    "api-prod": {
      urlTemplate: "https://api.osv.dev/v1/vulns/{id}",
    },
  };

  function syntaxHighlight(json) {
    if (typeof json != 'string') {
      json = JSON.stringify(json, undefined, 2);
    }
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, function (match) {
      var cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    });
  }

  async function fetchData(sourceKey, vulnId) {
    if (!sourceKey || !vulnId) return null;

    const config = sourceConfigMap[sourceKey];
    let url;

    if (config.bucket) {
      const path = config.pathTemplate.replace("{id}", vulnId);
      url = `/triage/proxy?bucket=${config.bucket}&path=${encodeURIComponent(path)}`;
    } else if (config.urlTemplate || sourceKey === 'cve-org') {
      let targetUrl;
      if (sourceKey === 'cve-org') {
        // Construct GitHub raw URL for CVE data
        // Format: https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/<year>/<seq_prefix>xxx/<CVE-ID>.json
        const match = vulnId.match(/^CVE-(\d{4})-(\d+)$/i);
        if (match) {
          const year = match[1];
          const seq = match[2];
          const seqPrefix = seq.length > 3 ? seq.slice(0, -3) : '0';
          targetUrl = `https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/${year}/${seqPrefix}xxx/${vulnId.toUpperCase()}.json`;
        } else {
          throw new Error("Invalid CVE ID format for GitHub source");
        }
      } else {
        targetUrl = config.urlTemplate.replace("{id}", vulnId);
      }

      if (config.useProxy || sourceKey === 'cve-org') {
        url = `/triage/proxy?url=${encodeURIComponent(targetUrl)}`;
      } else {
        url = targetUrl;
      }
    } else {
        return Promise.reject("Invalid configuration");
    }

    const response = await fetch(url);
    if (!response.ok) {
        if (response.status === 404) {
             throw new Error("Not Found");
        }
        throw new Error(`Error: ${response.statusText}`);
    }
    return response.json();
  }

  function updateColumn(column) {
    const select = column.querySelector(".source-select");
    const contentPre = column.querySelector(".json-content");
    const spinner = column.querySelector(".loading-spinner");
    const sourceKey = select.value;
    const vulnId = vulnIdInput.value.trim();

    if (!sourceKey) {
        contentPre.textContent = "Select a source to view content";
        return;
    }

    if (!vulnId) {
      contentPre.textContent = "Please enter a Vulnerability ID";
      return;
    }

    spinner.classList.remove("hidden");
    contentPre.textContent = "";

    fetchData(sourceKey, vulnId)
      .then((data) => {
        contentPre.innerHTML = syntaxHighlight(data);
      })
      .catch((error) => {
        contentPre.textContent = error.message;
      })
      .finally(() => {
        spinner.classList.add("hidden");
      });
  }

  loadBtn.addEventListener("click", () => {
    columns.forEach((col) => updateColumn(col));
  });

  // Also handle Enter key on the input field
  vulnIdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
          columns.forEach((col) => updateColumn(col));
      }
  });

  // Individual column updates when dropdown changes
  columns.forEach((col) => {
    const select = col.querySelector(".source-select");
    select.addEventListener("change", () => {
        if (vulnIdInput.value.trim()) {
            updateColumn(col);
        }
    });
  });
});
