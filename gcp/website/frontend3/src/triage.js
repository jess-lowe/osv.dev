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
      proxySource: "cve",
    },
    "nvd-api": {
      proxySource: "nvd",
    },
    // Test Instance
    "test-nvd": {
      proxySource: "test-nvd",
    },
    "test-cve5": {
      proxySource: "test-cve5",
    },
    "test-osv": {
      proxySource: "test-osv",
    },
    "test-nvd-metrics": {
      proxySource: "test-nvd-metrics",
    },
    "test-cve5-metrics": {
      proxySource: "test-cve5-metrics",
    },
    // Prod Instance
    "prod-nvd": {
      proxySource: "prod-nvd",
    },
    "prod-cve5": {
      proxySource: "prod-cve5",
    },
    "prod-osv": {
      proxySource: "prod-osv",
    },
    "prod-nvd-metrics": {
      proxySource: "prod-nvd-metrics",
    },
    "prod-cve5-metrics": {
      proxySource: "prod-cve5-metrics",
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
    if (typeof json !== 'string') {
      json = JSON.stringify(json, undefined, 2);
    }
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, function (match) {
      let cls = 'json-number';
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
    const config = sourceConfigMap[sourceKey];
    let url;

    if (config.proxySource) {
      url = `/triage/proxy?source=${config.proxySource}&id=${vulnId}`;
    } else if (config.urlTemplate) {
      url = config.urlTemplate.replace("{id}", vulnId);
    } else {
        return Promise.reject(new Error("Invalid configuration"));
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
