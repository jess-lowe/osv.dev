import "./generate.scss";
import "./osv-tabs.js";

document.addEventListener("DOMContentLoaded", function () {
  const osvForm = document.getElementById("osv-form");
  const jsonOutput = document.getElementById("json-output");
  const osvPreviewOutput = document.getElementById("osv-preview-output");
  const loadIdInput = document.getElementById("load-id");
  const loadBtn = document.getElementById("load-btn");
  const copyJsonBtn = document.getElementById("copy-json-btn");
  const downloadJsonBtn = document.getElementById("download-json-btn");

  // Dynamic list buttons
  const addPackageBtn = document.getElementById("add-package-btn");
  const addSeverityBtn = document.getElementById("add-severity-btn");
  const addReferenceBtn = document.getElementById("add-reference-btn");
  const addCreditBtn = document.getElementById("add-credit-btn");

  const packagesList = document.getElementById("packages-list");
  const severityList = document.getElementById("severity-list");
  const referencesList = document.getElementById("references-list");
  const creditsList = document.getElementById("credits-list");

  // Preview tabs
  const previewTabBtns = document.querySelectorAll(".preview-tab-btn");
  const previewContents = document.querySelectorAll(".preview-content");

  previewTabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.target;
      previewTabBtns.forEach(b => b.classList.toggle("active", b === btn));
      previewContents.forEach(c => c.classList.toggle("active", c.id === target));
      if (target === "osv-preview-tab") {
        updateOsvPreview();
      }
    });
  });

  function getFormData() {
    const formData = new FormData(osvForm);
    const data = {
      id: formData.get("id") || undefined,
      summary: formData.get("summary") || undefined,
      details: formData.get("details") || undefined,
      published: formData.get("published") ? new Date(formData.get("published")).toISOString() : undefined,
      modified: formData.get("modified") ? new Date(formData.get("modified")).toISOString() : new Date().toISOString(),
      affected: [],
      severity: [],
      references: [],
      credits: []
    };

    // Packages
    document.querySelectorAll(".package-item").forEach(pkgEl => {
      const ecosystem = pkgEl.querySelector(".package-ecosystem").value;
      const name = pkgEl.querySelector(".package-name").value;
      const purl = pkgEl.querySelector(".package-purl").value;

      const pkg = {
        ranges: [],
        versions: [] // TODO: Add versions support if needed
      };

      if (name || ecosystem || purl) {
        pkg.package = {
          ecosystem: ecosystem || undefined,
          name: name || undefined,
          purl: purl || undefined
        };
      }

      pkgEl.querySelectorAll(".range-item").forEach(rangeEl => {
        const range = {
          type: rangeEl.querySelector(".range-type").value,
          repo: rangeEl.querySelector(".range-repo").value || undefined,
          events: []
        };
        rangeEl.querySelectorAll(".event-item").forEach(eventEl => {
          const type = eventEl.querySelector(".event-type").value;
          const value = eventEl.querySelector(".event-value").value;
          if (value) {
            range.events.push({ [type]: value });
          }
        });
        if (range.events.length > 0) {
          pkg.ranges.push(range);
        }
      });

      if (pkg.package || pkg.ranges.length > 0) {
        data.affected.push(pkg);
      }
    });

    // Severity
    document.querySelectorAll(".severity-item").forEach(sevEl => {
      const type = sevEl.querySelector(".severity-type").value;
      const score = sevEl.querySelector(".severity-score").value;
      if (score) {
        data.severity.push({ type, score });
      }
    });

    // References
    document.querySelectorAll(".reference-item").forEach(refEl => {
      const type = refEl.querySelector(".reference-type").value;
      const url = refEl.querySelector(".reference-url").value;
      if (url) {
        data.references.push({ type, url });
      }
    });

    // Credits
    document.querySelectorAll(".credit-item").forEach(creditEl => {
      const name = creditEl.querySelector(".credit-name").value;
      const type = creditEl.querySelector(".credit-type").value;
      if (name) {
        data.credits.push({ name, type });
      }
    });

    // Clean up empty arrays
    if (data.affected.length === 0) delete data.affected;
    if (data.severity.length === 0) delete data.severity;
    if (data.references.length === 0) delete data.references;
    if (data.credits.length === 0) delete data.credits;

    return data;
  }

  function validateData(data) {
    const errors = [];
    if (!data.summary) errors.push("Summary is recommended.");
    if (!data.affected || data.affected.length === 0) errors.push("At least one affected package/repo is recommended.");

    if (data.affected) {
      data.affected.forEach((aff, i) => {
        const hasPackageName = aff.package && aff.package.name;
        if (!hasPackageName && (!aff.ranges || aff.ranges.length === 0)) {
           errors.push(`Affected Item ${i+1}: Package Name or Range is required.`);
        }
        if (aff.ranges) {
          aff.ranges.forEach((range, j) => {
            if (!range.events || range.events.length === 0) {
              errors.push(`Affected Item ${i+1}, Range ${j+1}: At least one event is required.`);
            }
          });
        }
      });
    }

    const errorEl = document.getElementById("validation-errors");
    if (errors.length > 0) {
      errorEl.innerHTML = "<strong>Validation Suggestions:</strong><ul>" + errors.map(e => `<li>${e}</li>`).join("") + "</ul>";
      errorEl.classList.add("visible");
    } else {
      errorEl.innerHTML = "";
      errorEl.classList.remove("visible");
    }
  }

  function updateJsonOutput() {
    const data = getFormData();
    jsonOutput.textContent = JSON.stringify(data, null, 2);
    validateData(data);
  }

  async function updateOsvPreview() {
    const data = getFormData();
    osvPreviewOutput.innerHTML = "Loading preview...";
    try {
      const response = await fetch("/api/render_preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      if (response.ok) {
        osvPreviewOutput.innerHTML = await response.text();
        // Re-run any scripts if needed (e.g. for tabs)
        // Since we are just inserting HTML, custom elements like <osv-tabs> should work if already defined
      } else {
        osvPreviewOutput.innerHTML = "Error rendering preview: " + await response.text();
      }
    } catch (e) {
      osvPreviewOutput.innerHTML = "Error: " + e.message;
    }
  }

  function addDynamicItem(templateId, listId, setupFn) {
    const template = document.getElementById(templateId);
    const list = document.getElementById(listId);
    const clone = template.content.cloneNode(true);
    const item = clone.querySelector(":first-child");

    if (setupFn) setupFn(item);

    item.querySelector(".remove-btn").addEventListener("click", () => {
      item.remove();
      updateJsonOutput();
    });

    item.querySelectorAll("input, select, textarea").forEach(el => {
      el.addEventListener("input", updateJsonOutput);
    });

    list.appendChild(clone);
    updateJsonOutput();
    return item;
  }

  addPackageBtn.addEventListener("click", () => {
    addDynamicItem("package-template", "packages-list", (item) => {
      const addRangeBtn = item.querySelector(".add-range-btn");
      const rangesList = item.querySelector(".ranges-list");
      addRangeBtn.addEventListener("click", () => {
        addRangeToPackage(rangesList);
      });
    });
  });

  function addRangeToPackage(rangesList) {
    const template = document.getElementById("range-template");
    const clone = template.content.cloneNode(true);
    const item = clone.querySelector(".range-item");

    item.querySelector(".remove-btn").addEventListener("click", () => {
      item.remove();
      updateJsonOutput();
    });

    item.querySelectorAll("input, select").forEach(el => {
      el.addEventListener("input", updateJsonOutput);
    });

    const addEventBtn = item.querySelector(".add-event-btn");
    const eventsList = item.querySelector(".events-list");
    addEventBtn.addEventListener("click", () => {
      addEventToRange(eventsList);
    });

    rangesList.appendChild(clone);
    updateJsonOutput();
  }

  function addEventToRange(eventsList) {
    const template = document.getElementById("event-template");
    const clone = template.content.cloneNode(true);
    const item = clone.querySelector(".event-item");

    item.querySelector(".remove-btn").addEventListener("click", () => {
      item.remove();
      updateJsonOutput();
    });

    item.querySelectorAll("input, select").forEach(el => {
      el.addEventListener("input", updateJsonOutput);
    });

    eventsList.appendChild(clone);
    updateJsonOutput();
  }

  addSeverityBtn.addEventListener("click", () => {
    addDynamicItem("severity-template", "severity-list");
  });

  addReferenceBtn.addEventListener("click", () => {
    addDynamicItem("reference-template", "references-list");
  });

  addCreditBtn.addEventListener("click", () => {
    addDynamicItem("credit-template", "credits-list");
  });

  osvForm.addEventListener("input", updateJsonOutput);

  // Load existing entry
  loadBtn.addEventListener("click", async () => {
    const id = loadIdInput.value.trim();
    if (!id) return;

    loadBtn.disabled = true;
    loadBtn.textContent = "Loading...";

    try {
      const response = await fetch(`https://api.osv.dev/v1/vulns/${id}`);
      if (response.ok) {
        const data = await response.json();
        fillForm(data);
      } else {
        alert("Vulnerability not found: " + id);
      }
    } catch (e) {
      alert("Error loading vulnerability: " + e.message);
    } finally {
      loadBtn.disabled = false;
      loadBtn.textContent = "Load";
    }
  });

  function fillForm(data) {
    // Clear existing dynamic lists
    packagesList.innerHTML = "";
    severityList.innerHTML = "";
    referencesList.innerHTML = "";
    creditsList.innerHTML = "";

    // General info
    document.getElementById("id").value = data.id || "";
    document.getElementById("summary").value = data.summary || "";
    document.getElementById("details").value = data.details || "";
    if (data.published) {
        document.getElementById("published").value = data.published.slice(0, 16);
    }
    if (data.modified) {
        document.getElementById("modified").value = data.modified.slice(0, 16);
    }

    // Affected
    if (data.affected) {
      data.affected.forEach(aff => {
        const pkgItem = addPackageToForm(aff);
      });
    }

    // Severity
    if (data.severity) {
      data.severity.forEach(sev => {
        const item = addDynamicItem("severity-template", "severity-list");
        item.querySelector(".severity-type").value = sev.type;
        item.querySelector(".severity-score").value = sev.score;
      });
    }

    // References
    if (data.references) {
      data.references.forEach(ref => {
        const item = addDynamicItem("reference-template", "references-list");
        item.querySelector(".reference-type").value = ref.type;
        item.querySelector(".reference-url").value = ref.url;
      });
    }

    // Credits
    if (data.credits) {
      data.credits.forEach(credit => {
        const item = addDynamicItem("credit-template", "credits-list");
        item.querySelector(".credit-name").value = credit.name;
        item.querySelector(".credit-type").value = credit.type || "FINDER";
      });
    }

    updateJsonOutput();
  }

  function addPackageToForm(aff) {
    const pkgItem = addDynamicItem("package-template", "packages-list", (item) => {
      const addRangeBtn = item.querySelector(".add-range-btn");
      const rangesList = item.querySelector(".ranges-list");
      addRangeBtn.addEventListener("click", () => {
        addRangeToPackage(rangesList);
      });
    });

    if (aff.package) {
      pkgItem.querySelector(".package-ecosystem").value = aff.package.ecosystem || "";
      pkgItem.querySelector(".package-name").value = aff.package.name || "";
      pkgItem.querySelector(".package-purl").value = aff.package.purl || "";
    } else {
      pkgItem.querySelector(".package-ecosystem").value = "";
      pkgItem.querySelector(".package-name").value = "";
      pkgItem.querySelector(".package-purl").value = "";
    }

    if (aff.ranges) {
      aff.ranges.forEach(range => {
        const rangesList = pkgItem.querySelector(".ranges-list");
        const rangeItem = addRangeToPackageFromData(rangesList, range);
      });
    }
    return pkgItem;
  }

  function addRangeToPackageFromData(rangesList, rangeData) {
    const template = document.getElementById("range-template");
    const clone = template.content.cloneNode(true);
    const item = clone.querySelector(".range-item");

    item.querySelector(".remove-btn").addEventListener("click", () => {
      item.remove();
      updateJsonOutput();
    });

    item.querySelectorAll("input, select").forEach(el => {
      el.addEventListener("input", updateJsonOutput);
    });

    item.querySelector(".range-type").value = rangeData.type;
    item.querySelector(".range-repo").value = rangeData.repo || "";

    const addEventBtn = item.querySelector(".add-event-btn");
    const eventsList = item.querySelector(".events-list");
    addEventBtn.addEventListener("click", () => {
      addEventToRange(eventsList);
    });

    if (rangeData.events) {
      rangeData.events.forEach(eventData => {
        const eventType = Object.keys(eventData)[0];
        const eventValue = eventData[eventType];
        addEventToRangeFromData(eventsList, eventType, eventValue);
      });
    }

    rangesList.appendChild(clone);
    return item;
  }

  function addEventToRangeFromData(eventsList, type, value) {
    const template = document.getElementById("event-template");
    const clone = template.content.cloneNode(true);
    const item = clone.querySelector(".event-item");

    item.querySelector(".remove-btn").addEventListener("click", () => {
      item.remove();
      updateJsonOutput();
    });

    item.querySelectorAll("input, select").forEach(el => {
      el.addEventListener("input", updateJsonOutput);
    });

    item.querySelector(".event-type").value = type;
    item.querySelector(".event-value").value = value;

    eventsList.appendChild(clone);
  }

  // Actions
  copyJsonBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(jsonOutput.textContent).then(() => {
      const originalText = copyJsonBtn.textContent;
      copyJsonBtn.textContent = "Copied!";
      setTimeout(() => copyJsonBtn.textContent = originalText, 2000);
    });
  });

  downloadJsonBtn.addEventListener("click", () => {
    const data = getFormData();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = (data.id || "osv-entry") + ".json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Initial state: add one package
  addPackageBtn.click();

  const now = new Date();
  const nowIso = now.toISOString().slice(0, 16);
  document.getElementById("published").value = nowIso;
  document.getElementById("modified").value = nowIso;

  updateJsonOutput();
});
