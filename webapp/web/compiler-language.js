(() => {
  const body = document.getElementById("compiler-lang-body");
  const storagePrefix = () => {
    const email = localStorage.getItem("flang.auth.activeEmail") || "guest";
    return `flang.compilerLang.${encodeURIComponent(email)}.`;
  };
  let currentSample = null;
  let questionIndex = 0;
  let answers = [];

  const readProgress = (sample) => {
    try {
      return JSON.parse(localStorage.getItem(storagePrefix() + sample.id)) || {};
    } catch (error) {
      console.warn("Could not read Compiler Language progress.", error);
      return {};
    }
  };

  const saveProgress = (sample, progress) => localStorage.setItem(storagePrefix() + sample.id, JSON.stringify(progress));
  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  const learnerName = () => localStorage.getItem(storagePrefix() + "learner") || "";

  function renderOverview(query = "", category = "All") {
    currentSample = null;
    const categories = ["All", "Language", "Runtime", "Security", "Reports"];
    const normalizedQuery = query.trim().toLowerCase();
    const visibleSamples = COMPILER_SAMPLES.filter((sample, index) => {
      const sampleCategory = index === 0 ? "Language" : index === 1 ? "Language" : index === 2 ? "Runtime" : index === 3 ? "Security" : "Reports";
      const matchesCategory = category === "All" || sampleCategory === category;
      const matchesQuery = !normalizedQuery || `${sample.title} ${sample.summary}`.toLowerCase().includes(normalizedQuery);
      return matchesCategory && matchesQuery;
    });

    body.innerHTML = `
      <div class="compiler-hero">
        <div class="compiler-hero-copy">
          <span class="compiler-eyebrow">FLANG / ONLINE LEARNING</span>
          <h2>Understand the language behind the investigation.</h2>
          <p>Explore guided lessons on syntax, execution, evidence, and reports. Complete a sample to unlock its certificate.</p>
        </div>
        <div class="compiler-hero-mark" aria-hidden="true">&lt;/&gt;</div>
      </div>
      <div class="compiler-toolbar">
        <label class="compiler-name">Learner name
          <input id="compiler-learner" type="text" maxlength="60" placeholder="Enter your name" value="${escapeHtml(learnerName())}">
        </label>
        <span class="compiler-summary">${COMPILER_SAMPLES.filter((sample) => readProgress(sample).passed).length} of ${COMPILER_SAMPLES.length} certificates earned</span>
      </div>
      <div class="compiler-discovery">
        <label class="compiler-search">
          <span aria-hidden="true">⌕</span>
          <input id="compiler-search" type="search" placeholder="Search FLANG lessons..." value="${escapeHtml(query)}" aria-label="Search FLANG lessons">
        </label>
        <div class="compiler-filters" role="group" aria-label="Filter lessons">
          ${categories.map((item) => `<button class="compiler-filter ${item === category ? "is-active" : ""}" data-category="${item}">${item}</button>`).join("")}
        </div>
      </div>
      <div class="compiler-sample-grid">
        ${visibleSamples.length ? visibleSamples.map((sample) => {
          const progress = readProgress(sample);
          const passed = Boolean(progress.passed);
          return `<article class="compiler-sample-card">
            <div class="sample-card-top"><span class="sample-index">${sample.title.split(":")[0]}</span><span class="certificate-state ${passed ? "is-unlocked" : ""}">${passed ? "✓ UNLOCKED" : "▣ LOCKED"}</span></div>
            <h2>${escapeHtml(sample.title.split(": ").slice(1).join(": "))}</h2>
            <p>${escapeHtml(sample.summary)}</p>
            <div class="sample-meta"><span>${progress.bestScore === undefined ? "Not attempted" : `Best score: ${progress.bestScore}%`}</span><span>${passed ? "PASS" : progress.attempts ? "IN PROGRESS" : "NOT STARTED"}</span></div>
            <button class="btn-primary compiler-open" data-sample="${sample.id}">${passed ? "Review Sample" : "Open Sample"}</button>
            ${passed ? `<button class="btn-secondary compiler-certificate" data-sample="${sample.id}">View Certificate</button>` : ""}
          </article>`;
        }).join("") : `<div class="compiler-empty">No lessons match that search. Try a different topic.</div>`}
      </div>`;
    document.getElementById("compiler-learner").addEventListener("change", (event) => localStorage.setItem(storagePrefix() + "learner", event.target.value.trim()));
    document.getElementById("compiler-search").addEventListener("input", (event) => renderOverview(event.target.value, category));
    body.querySelectorAll(".compiler-filter").forEach((button) => button.addEventListener("click", () => renderOverview(query, button.dataset.category)));
    body.querySelectorAll(".compiler-open").forEach((button) => button.addEventListener("click", () => renderSample(button.dataset.sample)));
    body.querySelectorAll(".compiler-certificate").forEach((button) => button.addEventListener("click", () => renderCertificate(button.dataset.sample)));
  }

  function renderSample(sampleId) {
    currentSample = COMPILER_SAMPLES.find((sample) => sample.id === sampleId);
    const progress = readProgress(currentSample);
    body.innerHTML = `<div class="compiler-detail">
      <button class="btn-secondary compiler-back">← All Samples</button>
      <span class="page-kicker">${currentSample.title.split(":")[0]}</span>
      <h2>${escapeHtml(currentSample.title.split(": ").slice(1).join(": "))}</h2>
      <p>${escapeHtml(currentSample.summary)}</p>
      <div class="compiler-detail-meta">Pass mark: ${currentSample.passingPercent}% · ${progress.attempts || 0} attempt(s) · Best: ${progress.bestScore === undefined ? "—" : progress.bestScore + "%"}</div>
      <button class="btn-primary compiler-start">Start Quiz</button>
    </div>`;
    body.querySelector(".compiler-back").addEventListener("click", () => renderOverview());
    body.querySelector(".compiler-start").addEventListener("click", startQuiz);
  }

  function startQuiz() {
    questionIndex = 0;
    answers = [];
    renderQuestion();
  }

  function renderQuestion() {
    const question = currentSample.questions[questionIndex];
    body.innerHTML = `<div class="compiler-quiz">
      <button class="btn-secondary compiler-back">← Exit Quiz</button>
      <div class="quiz-progress">Question ${questionIndex + 1} of ${currentSample.questions.length}<span><i style="width:${((questionIndex + 1) / currentSample.questions.length) * 100}%"></i></span></div>
      <h2>${escapeHtml(question.text)}</h2>
      <div class="quiz-options">${question.options.map((option, index) => `<button class="quiz-option" data-index="${index}"><span>${String.fromCharCode(65 + index)}</span>${escapeHtml(option)}</button>`).join("")}</div>
      <button class="btn-primary quiz-next" disabled>${questionIndex === currentSample.questions.length - 1 ? "Submit Quiz" : "Next Question →"}</button>
    </div>`;
    body.querySelector(".compiler-back").addEventListener("click", () => renderSample(currentSample.id));
    let selected = null;
    body.querySelectorAll(".quiz-option").forEach((option) => option.addEventListener("click", () => {
      selected = Number(option.dataset.index);
      body.querySelectorAll(".quiz-option").forEach((item) => item.classList.toggle("selected", item === option));
      body.querySelector(".quiz-next").disabled = false;
    }));
    body.querySelector(".quiz-next").addEventListener("click", () => {
      answers.push(selected);
      if (questionIndex < currentSample.questions.length - 1) {
        questionIndex += 1;
        renderQuestion();
      } else {
        finishQuiz();
      }
    });
  }

  function finishQuiz() {
    const score = Math.round((answers.filter((answer, index) => answer === currentSample.questions[index].correctIndex).length / currentSample.questions.length) * 100);
    const previous = readProgress(currentSample);
    const progress = { ...previous, attempts: (previous.attempts || 0) + 1, bestScore: Math.max(previous.bestScore === undefined ? 0 : previous.bestScore, score) };
    if (score >= currentSample.passingPercent) {
      progress.passed = true;
      progress.passedAt = new Date().toISOString();
    }
    saveProgress(currentSample, progress);
    const missed = currentSample.questions.map((question, index) => answers[index] === question.correctIndex ? "" : `<li><strong>${escapeHtml(question.text)}</strong><br>Correct answer: ${escapeHtml(question.options[question.correctIndex])}</li>`).join("");
    body.innerHTML = `<div class="quiz-result ${score >= currentSample.passingPercent ? "is-pass" : "is-fail"}">
      <span class="result-label">${score >= currentSample.passingPercent ? "CERTIFICATION PASSED" : "REVIEW REQUIRED"}</span>
      <h2>${score}%</h2><p>${score >= currentSample.passingPercent ? "Certificate unlocked. Your best score is saved in this browser." : `The passing mark is ${currentSample.passingPercent}%. Review the missed answers and try again.`}</p>
      ${missed ? `<ul class="missed-questions">${missed}</ul>` : ""}
      <button class="btn-primary compiler-${score >= currentSample.passingPercent ? "certificate" : "retake"}">${score >= currentSample.passingPercent ? "View Certificate" : "Retake Quiz"}</button>
      <button class="btn-secondary compiler-overview">Back to Samples</button>
    </div>`;
    body.querySelector(".compiler-overview").addEventListener("click", () => renderOverview());
    body.querySelector(".compiler-" + (score >= currentSample.passingPercent ? "certificate" : "retake")).addEventListener("click", () => score >= currentSample.passingPercent ? renderCertificate(currentSample.id) : startQuiz());
  }

  function renderCertificate(sampleId) {
    const sample = COMPILER_SAMPLES.find((item) => item.id === sampleId);
    const progress = readProgress(sample);
    if (!progress.passed) return renderOverview();
    const date = new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    const course = sample.title.split(": ").slice(1).join(": ");
    const certificateUrl = `/certificate.html?name=${encodeURIComponent(learnerName() || "FLANG Learner")}&course=${encodeURIComponent(course)}&date=${encodeURIComponent(date)}&v=${Date.now()}`;
    body.innerHTML = `<div class="certificate-actions">
        <button class="btn-secondary certificate-back">← Back</button>
        <button class="btn-primary certificate-download">Download Certificate</button>
      </div>
      <iframe class="certificate-frame" title="FLANG certificate" src="${certificateUrl}" loading="eager"></iframe>`;
    body.querySelector(".certificate-back").addEventListener("click", () => renderOverview());
    body.querySelector(".certificate-download").textContent = "Download Certificate JPG";
    body.querySelector(".certificate-download").addEventListener("click", () => downloadCertificate(sample.id));
  }

  async function downloadCertificate(sampleId) {
    const frame = body.querySelector(".certificate-frame");
    if (!frame || !frame.contentDocument || !window.html2canvas) {
      throw new Error("Certificate JPG tools are not available. Refresh the page and try again.");
    }
    const certificateDocument = frame.contentDocument;
    await certificateDocument.fonts.ready;
    await Promise.all([
      certificateDocument.fonts.load('italic 600 4rem "Cormorant Garamond"'),
      certificateDocument.fonts.load('400 4rem "Great Vibes"'),
      certificateDocument.fonts.load('500 1rem Inter'),
    ]);
    await Promise.all(Array.from(certificateDocument.images).map((image) => (
      image.complete && image.naturalWidth > 0
        ? Promise.resolve()
        : new Promise((resolve) => {
            image.addEventListener("load", resolve, { once: true });
            image.addEventListener("error", resolve, { once: true });
          })
    )));
    const originalImageSources = new Map();
    await Promise.all(Array.from(certificateDocument.images).map(async (image) => {
      const response = await fetch(image.currentSrc || image.src);
      const blob = await response.blob();
      const dataUrl = await new Promise((resolve) => {
        const reader = new FileReader();
        reader.addEventListener("load", () => resolve(reader.result), { once: true });
        reader.readAsDataURL(blob);
      });
      originalImageSources.set(image, image.src);
      image.src = dataUrl;
      await image.decode();
    }));
    const originalWidth = frame.style.width;
    const originalHeight = frame.style.height;
    frame.style.width = "960px";
    frame.style.height = "700px";
    const captureStyle = certificateDocument.createElement("style");
    captureStyle.textContent = `
      html, body { width: 960px !important; min-width: 960px !important; overflow: visible !important; }
      .certificate-shell { width: 960px !important; min-width: 960px !important; }
      .content { grid-template-columns: 220px 1fr !important; gap: 24px !important; padding: 42px 46px 26px 42px !important; }
      .right { padding: 148px 22px 0 0 !important; }
      .certificate-heading { top: 122px !important; }
    `;
    certificateDocument.head.appendChild(captureStyle);
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const shell = certificateDocument.querySelector(".certificate-shell");
    const bounds = shell.getBoundingClientRect();
    const canvas = await window.html2canvas(shell, {
      scale: 2,
      useCORS: true,
      foreignObjectRendering: true,
      backgroundColor: "#f3f4f2",
      width: Math.ceil(bounds.width),
      height: Math.ceil(bounds.height),
      windowWidth: 960,
      windowHeight: Math.ceil(bounds.height),
      logging: false,
    });
    captureStyle.remove();
    frame.style.width = originalWidth;
    frame.style.height = originalHeight;
    originalImageSources.forEach((source, image) => {
      image.src = source;
    });
    const downloadLink = document.createElement("a");
    downloadLink.href = canvas.toDataURL("image/jpeg", 0.95);
    downloadLink.download = `flang-${sampleId}-certificate.jpg`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    downloadLink.remove();
  }

  renderOverview();
})();
