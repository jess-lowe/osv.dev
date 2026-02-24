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

  async function fetchData(sourceKey, vulnId) {
    if (!sourceKey || !vulnId) return null;

    const config = sourceConfigMap[sourceKey];
    let url;

    if (config.bucket) {
      const path = config.pathTemplate.replace("{id}", vulnId);
      url = `/triage/proxy?bucket=${config.bucket}&path=${encodeURIComponent(path)}`;
    } else if (config.urlTemplate) {
      url = config.urlTemplate.replace("{id}", vulnId);
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
        contentPre.textContent = JSON.stringify(data, null, 2);
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
  vulnIdInput.addEventListener("keyup", (e) => {
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
