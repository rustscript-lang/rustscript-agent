(() => {
  'use strict';

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const root = document.documentElement;

  // Mobile navigation
  const menuButton = document.querySelector('.menu-toggle');
  const menu = document.querySelector('.nav-links');
  if (menuButton && menu) {
    const closeMenu = (restoreFocus = false) => {
      menuButton.setAttribute('aria-expanded', 'false');
      menu.classList.remove('is-open');
      if (restoreFocus) menuButton.focus();
    };
    menuButton.addEventListener('click', () => {
      const open = menuButton.getAttribute('aria-expanded') !== 'true';
      menuButton.setAttribute('aria-expanded', String(open));
      menu.classList.toggle('is-open', open);
    });
    menu.addEventListener('click', event => {
      if (event.target.closest('a')) closeMenu();
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && menuButton.getAttribute('aria-expanded') === 'true') {
        closeMenu(true);
      }
    });
  }

  // Reveal sections progressively; content remains complete without JS.
  const revealItems = [...document.querySelectorAll('[data-reveal]')];
  if ('IntersectionObserver' in window && !reducedMotion.matches) {
    const revealObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-revealed');
          revealObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -5% 0px' });
    revealItems.forEach(item => revealObserver.observe(item));
  } else {
    revealItems.forEach(item => item.classList.add('is-revealed'));
  }

  // Architecture tabs
  const tablist = document.querySelector('.stage-tabs');
  const tabs = [...document.querySelectorAll('.stage-tab[data-stage]')];
  const panels = [...document.querySelectorAll('.stage-panel')];
  if (tablist) {
    tablist.setAttribute('role', 'tablist');
    tablist.setAttribute('aria-orientation', 'vertical');
  }
  tabs.forEach(tab => {
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', tab.getAttribute('href').slice(1));
  });
  panels.forEach(panel => {
    const tab = tabs.find(item => item.getAttribute('aria-controls') === panel.id);
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('tabindex', '0');
    if (tab) panel.setAttribute('aria-labelledby', tab.id);
  });
  const activateStage = (tab, moveFocus = false) => {
    tabs.forEach(item => {
      const selected = item === tab;
      item.classList.toggle('is-active', selected);
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
    });
    panels.forEach(panel => {
      const selected = panel.id === tab.getAttribute('aria-controls');
      panel.classList.toggle('is-active', selected);
      panel.hidden = !selected;
    });
    if (moveFocus) tab.focus();
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', event => {
      event.preventDefault();
      activateStage(tab);
    });
    tab.addEventListener('keydown', event => {
      let nextIndex = null;
      if (event.key === 'ArrowDown' || event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
      if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
      if (event.key === 'Home') nextIndex = 0;
      if (event.key === 'End') nextIndex = tabs.length - 1;
      if (nextIndex !== null) {
        event.preventDefault();
        activateStage(tabs[nextIndex], true);
      }
    });
  });
  if (tabs[0]) activateStage(tabs[0]);

  // Tool Graph generations change future admissions, never existing run pins.
  const graphControls = [...document.querySelectorAll('.graph-state-control[data-graph-state]')];
  const graphDemo = document.querySelector('.graph-demo');
  const graphStatus = document.querySelector('#graph-status');
  const activateGraphState = state => {
    const activeControl = graphControls.find(control => control.dataset.graphState === state);
    if (!activeControl) return;
    graphControls.forEach(control => {
      const selected = control === activeControl;
      control.classList.toggle('is-active', selected);
      control.setAttribute('aria-pressed', String(selected));
    });
    if (graphDemo) graphDemo.dataset.graphFocus = state;
    if (graphStatus) graphStatus.textContent = activeControl.dataset.graphAnnouncement;
  };
  graphControls.forEach(control => {
    control.addEventListener('click', () => activateGraphState(control.dataset.graphState));
  });
  const initialGraphControl = graphControls.find(control => control.getAttribute('aria-pressed') === 'true') ?? graphControls[0];
  if (initialGraphControl) activateGraphState(initialGraphControl.dataset.graphState);

  // Enable enhanced-only presentation after critical controls are wired.
  root.classList.remove('no-js');
  root.classList.add('js');

  // Durable stream simulation using the runtime's emitted event sequence.
  const streamRows = [...document.querySelectorAll('.event-row')];
  const eventConsole = document.querySelector('.event-console');
  const replayButton = document.querySelector('#event-replay');
  const outcomeButton = document.querySelector('#event-outcome');
  const cursor = document.querySelector('#replay-cursor');
  const cursorOutput = document.querySelector('#cursor-output');
  const streamState = document.querySelector('#stream-state');
  const streamLocale = (eventConsole?.dataset.locale || root.lang || 'en').toLowerCase().startsWith('zh') ? 'zh' : 'en';
  const streamCopy = {
    en: {
      showCommit: 'Show commit',
      showConflict: 'Show conflict',
      committed: 'status: committed',
      conflict: 'status: conflict',
      commitAnnouncements: [
        'Commit replay 1 of 5: run started.',
        'Commit replay 2 of 5: write_file requested.',
        'Commit replay 3 of 5: private managed view active.',
        'Commit replay 4 of 5: tool.output reports committed publication.',
        'Commit replay 5 of 5: tool.completed; receipt fx_7a29 read back.',
      ],
      conflictAnnouncements: [
        'Conflict replay 1 of 5: run started.',
        'Conflict replay 2 of 5: write_file requested.',
        'Conflict replay 3 of 5: private managed view active.',
        'Conflict replay 4 of 5: tool.output reports conflict; candidate retained.',
        'Conflict replay 5 of 5: tool.failed with effect_head_conflict.',
      ],
    },
    zh: {
      showCommit: '显示提交',
      showConflict: '显示冲突',
      committed: '状态：已提交',
      conflict: '状态：冲突',
      commitAnnouncements: [
        '提交重放 1/5：运行已开始。',
        '提交重放 2/5：已请求 write_file。',
        '提交重放 3/5：私有受管视图已启用。',
        '提交重放 4/5：tool.output 报告发布已提交。',
        '提交重放 5/5：tool.completed；已读回收据 fx_7a29。',
      ],
      conflictAnnouncements: [
        '冲突重放 1/5：运行已开始。',
        '冲突重放 2/5：已请求 write_file。',
        '冲突重放 3/5：私有受管视图已启用。',
        '冲突重放 4/5：tool.output 报告冲突；候选内容已保留。',
        '冲突重放 5/5：tool.failed，错误为 effect_head_conflict。',
      ],
    },
  }[streamLocale];
  let currentStep = 2;
  let conflictMode = false;
  let streamTimer = null;

  const paintStream = step => {
    if (!streamRows.length) return;
    currentStep = Math.max(0, Math.min(streamRows.length - 1, step));
    streamRows.forEach((row, index) => {
      row.classList.toggle('is-past', index < currentStep);
      row.classList.toggle('is-current', index === currentStep);
      row.classList.toggle('is-future', index > currentStep);
    });
    if (cursor) {
      cursor.style.left = `${(currentStep / (streamRows.length - 1)) * 100}%`;
      cursor.style.background = currentStep === streamRows.length - 1 ? (conflictMode ? 'var(--danger)' : 'var(--lime)') : 'var(--cyan)';
    }
    if (cursorOutput) cursorOutput.value = `${String(currentStep + 1).padStart(2, '0')} / 05`;
    if (streamState) {
      const announcements = conflictMode ? streamCopy.conflictAnnouncements : streamCopy.commitAnnouncements;
      streamState.textContent = announcements[currentStep];
      streamState.style.color = currentStep === 4 ? (conflictMode ? 'var(--danger)' : 'var(--lime)') : '';
    }
  };

  const replayStream = () => {
    window.clearInterval(streamTimer);
    paintStream(0);
    if (reducedMotion.matches) {
      paintStream(4);
      return;
    }
    streamTimer = window.setInterval(() => {
      if (currentStep >= streamRows.length - 1) {
        window.clearInterval(streamTimer);
      } else {
        paintStream(currentStep + 1);
      }
    }, 620);
  };

  if (replayButton) replayButton.addEventListener('click', replayStream);
  if (outcomeButton) {
    outcomeButton.addEventListener('click', () => {
      conflictMode = !conflictMode;
      if (eventConsole) eventConsole.classList.toggle('is-conflict', conflictMode);
      outcomeButton.textContent = conflictMode ? streamCopy.showCommit : streamCopy.showConflict;
      const decision = streamRows[streamRows.length - 2];
      const terminal = streamRows[streamRows.length - 1];
      if (decision) {
        const eventName = decision.querySelector('b');
        const state = decision.querySelector('span');
        if (eventName) eventName.textContent = 'tool.output';
        if (state) state.textContent = conflictMode ? streamCopy.conflict : streamCopy.committed;
      }
      if (terminal) {
        const eventName = terminal.querySelector('b');
        const state = terminal.querySelector('span');
        if (eventName) eventName.textContent = conflictMode ? 'tool.failed' : 'tool.completed';
        if (state) state.textContent = conflictMode ? 'effect_head_conflict' : 'fx_7a29';
      }
      paintStream(currentStep);
    });
  }
  paintStream(currentStep);

  // Scroll-linked runtime path
  const runtimeFigure = document.querySelector('.runtime-figure');
  let scrollQueued = false;
  const updateScrollProgress = () => {
    scrollQueued = false;
    if (!runtimeFigure) return;
    const rect = runtimeFigure.getBoundingClientRect();
    const viewport = window.innerHeight || 1;
    const progress = Math.max(0.04, Math.min(1, (viewport - rect.top) / (viewport * 0.72)));
    runtimeFigure.style.setProperty('--line-progress', progress.toFixed(3));
  };
  window.addEventListener('scroll', () => {
    if (!scrollQueued) {
      scrollQueued = true;
      window.requestAnimationFrame(updateScrollProgress);
    }
  }, { passive: true });
  updateScrollProgress();

  // Restrained pointer parallax
  if (runtimeFigure && !reducedMotion.matches && window.matchMedia('(pointer: fine)').matches) {
    const hero = document.querySelector('.hero');
    if (hero) {
      hero.addEventListener('pointermove', event => {
        const bounds = hero.getBoundingClientRect();
        const x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 8;
        const y = ((event.clientY - bounds.top) / bounds.height - 0.5) * 5;
        runtimeFigure.style.setProperty('--parallax-x', `${x.toFixed(2)}px`);
        runtimeFigure.style.setProperty('--parallax-y', `${y.toFixed(2)}px`);
      });
      hero.addEventListener('pointerleave', () => {
        runtimeFigure.style.setProperty('--parallax-x', '0px');
        runtimeFigure.style.setProperty('--parallax-y', '0px');
      });
    }
  }

  // Particles travel between lifecycle nodes only while the canvas can be seen.
  const canvas = document.querySelector('#runtime-particles');
  if (canvas && runtimeFigure) {
    const context = canvas.getContext('2d');
    const mobileCanvas = window.matchMedia('(max-width: 680px)');
    let animationFrame = 0;
    let width = 0;
    let height = 0;
    let pixelRatio = 1;
    let isIntersecting = false;
    const particles = Array.from({ length: 18 }, (_, index) => ({
      progress: (index / 18) + Math.random() * 0.04,
      speed: 0.000055 + Math.random() * 0.000055,
      radius: index % 5 === 0 ? 1.8 : 1,
      lane: (Math.random() - 0.5) * 22,
      alpha: 0.25 + Math.random() * 0.6
    }));

    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect();
      const nextPixelRatio = Math.min(window.devicePixelRatio || 1, 2);
      const nextWidth = rect.width;
      const nextHeight = rect.height;
      if (nextWidth === width && nextHeight === height && nextPixelRatio === pixelRatio) return;
      pixelRatio = nextPixelRatio;
      width = nextWidth;
      height = nextHeight;
      canvas.width = Math.round(width * pixelRatio);
      canvas.height = Math.round(height * pixelRatio);
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    };

    let lastTime = performance.now();
    const canAnimate = () => (
      !reducedMotion.matches &&
      !mobileCanvas.matches &&
      !document.hidden &&
      isIntersecting &&
      width > 0 &&
      height > 0 &&
      window.getComputedStyle(canvas).display !== 'none'
    );

    const stopParticles = () => {
      if (animationFrame) window.cancelAnimationFrame(animationFrame);
      animationFrame = 0;
      canvas.dataset.animationState = 'paused';
      context.clearRect(0, 0, width, height);
    };

    const drawParticles = time => {
      animationFrame = 0;
      if (!canAnimate()) {
        stopParticles();
        return;
      }
      const elapsed = Math.min(time - lastTime, 40);
      lastTime = time;
      context.clearRect(0, 0, width, height);
      const startX = width * 0.05;
      const distance = width * 0.90;
      const centerY = height * 0.5 - 14;
      particles.forEach((particle, index) => {
        particle.progress = (particle.progress + elapsed * particle.speed) % 1;
        const x = startX + distance * particle.progress;
        const wave = Math.sin(particle.progress * Math.PI * 10 + index) * particle.lane;
        const y = centerY + wave;
        const nearReview = particle.progress > 0.68 && particle.progress < 0.88;
        context.beginPath();
        context.arc(x, y, particle.radius, 0, Math.PI * 2);
        context.fillStyle = nearReview ? `rgba(255,179,65,${particle.alpha})` : `rgba(40,223,242,${particle.alpha})`;
        context.fill();
      });
      animationFrame = window.requestAnimationFrame(drawParticles);
    };

    const syncParticles = () => {
      resizeCanvas();
      if (!canAnimate()) {
        stopParticles();
        return;
      }
      canvas.dataset.animationState = 'running';
      if (!animationFrame) {
        lastTime = performance.now();
        animationFrame = window.requestAnimationFrame(drawParticles);
      }
    };

    resizeCanvas();
    window.addEventListener('resize', syncParticles, { passive: true });
    document.addEventListener('visibilitychange', syncParticles);
    reducedMotion.addEventListener('change', syncParticles);
    mobileCanvas.addEventListener('change', syncParticles);

    if ('ResizeObserver' in window) {
      const canvasResizeObserver = new ResizeObserver(syncParticles);
      canvasResizeObserver.observe(canvas);
    }

    if ('IntersectionObserver' in window) {
      const canvasVisibilityObserver = new IntersectionObserver(entries => {
        isIntersecting = entries.some(entry => entry.isIntersecting);
        syncParticles();
      });
      canvasVisibilityObserver.observe(canvas);
      syncParticles();
    } else {
      isIntersecting = true;
      syncParticles();
    }
  }
})();
