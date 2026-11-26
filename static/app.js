let csrfToken = "";

const loginSection = document.getElementById("login-section");

const memoSection = document.getElementById("memo-section");

const loginMessage = document.getElementById("login-message");

const memoMessage = document.getElementById("memo-message");

async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    credentials: "same-origin",
    cache: "no-store",
  });

  let data;

  try {
    data = await response.json();
  } catch {
    data = {
      error: "Invalid server response",
    };
  }

  if (!response.ok) {
    const error = new Error(data.error || "Request failed");

    error.status = response.status;

    throw error;
  }

  return data;
}

// ==========================================
// Session
// ==========================================

function showLogin() {
  csrfToken = "";

  loginSection.hidden = false;
  memoSection.hidden = true;

  document.getElementById("memo-list").replaceChildren();

  document.getElementById("memo-form").reset();
}

async function loadSession() {
  const data = await api("/api/session");

  csrfToken = data.csrf_token;

  document.getElementById("full-name").textContent = data.user.full_name;

  document.getElementById("github-id").textContent = data.user.github_id;

  loginSection.hidden = true;
  memoSection.hidden = false;

  await loadMemos();
}

// ==========================================
// Login
// ==========================================

document
  .getElementById("login-form")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    loginMessage.textContent = "";

    try {
      await api("/api/login", {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          username: document.getElementById("username").value,

          password: document.getElementById("password").value,
        }),
      });

      document.getElementById("login-form").reset();

      await loadSession();
    } catch (error) {
      loginMessage.textContent = error.message;
    }
  });

// ==========================================
// Load Memos
// ==========================================

async function loadMemos() {
  const memos = await api("/api/memos");

  const container = document.getElementById("memo-list");

  container.replaceChildren();

  document.getElementById("memo-count").textContent = `${memos.length}개`;

  if (memos.length === 0) {
    const empty = document.createElement("p");

    empty.textContent = "저장된 메모가 없습니다.";

    container.appendChild(empty);

    return;
  }

  for (const memo of memos) {
    const article = document.createElement("article");

    article.className = "card memo-item";

    const title = document.createElement("h3");

    const content = document.createElement("p");

    const date = document.createElement("p");

    content.className = "memo-content";
    date.className = "memo-date";

    // XSS Protection
    // User input is rendered as plain text.

    title.textContent = memo.title;
    content.textContent = memo.content;
    date.textContent = memo.created_at;

    article.append(title, content, date);

    container.appendChild(article);
  }
}

// ==========================================
// Create Memo
// ==========================================

document
  .getElementById("memo-form")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    const button = document.getElementById("save-button");

    button.disabled = true;

    memoMessage.textContent = "";

    try {
      const nonce = await api("/api/nonce");

      await api("/api/memos", {
        method: "POST",

        headers: {
          "Content-Type": "application/json",

          "X-CSRF-Token": csrfToken,

          "X-Request-Token": nonce.request_token,
        },

        body: JSON.stringify({
          title: document.getElementById("title").value,

          content: document.getElementById("content").value,
        }),
      });

      document.getElementById("memo-form").reset();

      await loadMemos();

      memoMessage.textContent = "메모 저장 완료";
    } catch (error) {
      if (error.status === 401) {
        showLogin();

        loginMessage.textContent = "세션이 만료되었습니다.";
      } else {
        memoMessage.textContent = error.message;
      }
    } finally {
      button.disabled = false;
    }
  });

// ==========================================
// Logout
// ==========================================

document.getElementById("logout-button").addEventListener("click", async () => {
  try {
    await api("/api/logout", {
      method: "POST",

      headers: {
        "X-CSRF-Token": csrfToken,
      },
    });

    showLogin();
  } catch (error) {
    if (error.status === 401) {
      showLogin();
    } else {
      memoMessage.textContent = error.message;
    }
  }
});

// ==========================================
// Initial Session Check
// ==========================================

loadSession().catch(() => {
  showLogin();
});
