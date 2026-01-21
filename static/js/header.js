// Header Component JavaScript

document.addEventListener("DOMContentLoaded", function () {
  // Check if we should skip notifications - only show on dashboard
  const currentPage = window.location.pathname;
  const allowedPages = ['/dashboard', '/admin-dashboard', 'dashboard'];
  const shouldShowNotifications = allowedPages.some(page => currentPage.includes(page));
  const shouldSkipNotifications = !shouldShowNotifications;
  
  // DOM Elements
  const searchInput = document.getElementById("searchInput");
  const searchResults = document.getElementById("searchResults");
  const notificationBtn = document.getElementById("notificationBtn");
  const notificationDropdown = document.getElementById("notificationDropdown");
  const notificationList = document.getElementById("notificationList");
  const notificationBadge = document.getElementById("notificationBadge");
  const closeNotifications = document.getElementById("closeNotifications");
  const profileBtn = document.getElementById("profileBtn");
  const profileDropdown = document.getElementById("profileDropdown");

  // State
  let searchTimeout;
  let notificationRefreshInterval;
  let lastNotificationCount = 0;

  // ==================== Real-time Notification System ====================

  // Load notifications on page load (skip if on deworming management page)
  if (!shouldSkipNotifications) {
    loadNotifications();
  }

  // Auto-refresh notifications every 15 seconds for real-time updates
  if (!shouldSkipNotifications) {
    notificationRefreshInterval = setInterval(loadNotifications, 15000);
  }

  if (notificationBtn && !shouldSkipNotifications) {
    notificationBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      const isVisible = notificationDropdown.style.display !== "none";
      notificationDropdown.style.display = isVisible ? "none" : "block";

      if (notificationDropdown.style.display === "block") {
        loadNotifications();
        // Refresh more frequently when dropdown is open (every 10 seconds)
        clearInterval(notificationRefreshInterval);
        notificationRefreshInterval = setInterval(loadNotifications, 10000);
      } else {
        // Slower refresh when dropdown is closed (every 15 seconds)
        clearInterval(notificationRefreshInterval);
        notificationRefreshInterval = setInterval(loadNotifications, 15000);
      }
    });

    if (closeNotifications) {
      closeNotifications.addEventListener("click", function (e) {
        e.stopPropagation();
        notificationDropdown.style.display = "none";
      });
    }
  }

  async function loadNotifications() {
    try {
      const response = await fetch("/api/notifications");

      if (!response.ok) {
        console.error("Notifications failed:", response.status);
        return;
      }

      const data = await response.json();

      // Filter out dismissed notifications
      const dismissedNotifications = getDismissedNotifications();
      const filteredNotifications = data.notifications.filter(
        (notif) => !dismissedNotifications.includes(notif.id)
      );

      if (filteredNotifications && filteredNotifications.length > 0) {
        displayNotifications(filteredNotifications);
        updateNotificationBadge(
          filteredNotifications.length,
          filteredNotifications.length
        );

        // Show toast notification for new high-priority items
        if (filteredNotifications.length > lastNotificationCount) {
          showNotificationToast(filteredNotifications[0]);
        }
        lastNotificationCount = filteredNotifications.length;
      } else {
        notificationList.innerHTML =
          '<div class="notification-empty">No notifications</div>';
        notificationBadge.style.display = "none";
        lastNotificationCount = 0;
      }
    } catch (error) {
      console.error("Notification error:", error);
    }
  }

  // Get dismissed notifications from localStorage
  function getDismissedNotifications() {
    const dismissed = localStorage.getItem("dismissedNotifications");
    return dismissed ? JSON.parse(dismissed) : [];
  }

  // Save dismissed notification to localStorage
  function dismissNotificationPermanently(notificationId) {
    const dismissed = getDismissedNotifications();
    if (!dismissed.includes(notificationId)) {
      dismissed.push(notificationId);
      localStorage.setItem("dismissedNotifications", JSON.stringify(dismissed));
    }

    // Optional: Send to backend for logging
    fetch("/api/notifications/dismiss", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ notification_id: notificationId }),
    }).catch((err) => console.log("Dismiss notification logged"));
  }

  function displayNotifications(notifications) {
    if (!notificationList) {
      console.error("notificationList element not found");
      return;
    }
    notificationList.innerHTML = "";

    notifications.forEach((notif) => {
      const item = document.createElement("div");
      item.className = `notification-item-content notification-${notif.type} priority-${notif.priority}`;
      item.setAttribute("data-notification-id", notif.id);

      // Format timestamp
      const date = new Date(notif.timestamp);
      const timeStr = formatTime(date);

      item.innerHTML = `
        <div class="notification-item-left">
          <i class="bx ${notif.icon}"></i>
        </div>
        <div class="notification-item-middle">
          <div class="notification-title">${escapeHtml(notif.title)}</div>
          <div class="notification-message">${escapeHtml(notif.message)}</div>
          <div class="notification-time">${timeStr}</div>
        </div>
        <div class="notification-item-right">
          <span class="notification-priority-badge ${
            notif.priority
          }">${notif.priority.toUpperCase()}</span>
          <button class="notification-close-btn" title="Dismiss notification">
            <i class="bx bx-x"></i>
          </button>
        </div>
      `;

      // Add click handler for navigation (on the content area, not the close button)
      if (notif.link) {
        const middleSection = item.querySelector(".notification-item-middle");
        middleSection.style.cursor = "pointer";
        middleSection.addEventListener("click", function () {
          window.location.href = notif.link;
        });
      }

      // Add close button handler
      const closeBtn = item.querySelector(".notification-close-btn");
      closeBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        const notificationId = item.getAttribute("data-notification-id");
        // Dismiss permanently (saves to localStorage)
        dismissNotificationPermanently(notificationId);

        item.style.animation = "slideOutRight 0.3s ease-in-out forwards";
        setTimeout(() => {
          item.remove();
          // Update badge count
          const remainingCount = notificationList.querySelectorAll(
            ".notification-item-content"
          ).length;
          if (remainingCount === 0) {
            notificationList.innerHTML =
              '<div class="notification-empty">No notifications</div>';
          }
          updateNotificationBadge(remainingCount, remainingCount);
        }, 300);
      });

      notificationList.appendChild(item);
    });
  }

  function updateNotificationBadge(total, unread) {
    if (!notificationBadge) {
      console.error("notificationBadge element not found");
      return;
    }
    if (total > 0) {
      notificationBadge.textContent = total > 99 ? "99+" : total;
      notificationBadge.style.display = "flex";
    } else {
      notificationBadge.style.display = "none";
    }
  }

  function showNotificationToast(notification) {
    // Create a toast notification (appears at top-right)
    const toast = document.createElement("div");
    toast.className = `notification-toast priority-${notification.priority}`;

    toast.innerHTML = `
      <div class="toast-icon">
        <i class="bx ${notification.icon}"></i>
      </div>
      <div class="toast-content">
        <div class="toast-title">${escapeHtml(notification.title)}</div>
        <div class="toast-message">${escapeHtml(notification.message)}</div>
      </div>
      <button class="toast-close" onclick="this.parentElement.remove()">
        <i class="bx bx-x"></i>
      </button>
    `;

    document.body.appendChild(toast);

    // Auto-remove after 8 seconds
    setTimeout(() => {
      if (toast.parentElement) {
        toast.remove();
      }
    }, 8000);
  }

  // ==================== Search Functionality ====================
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      const query = this.value.trim();

      clearTimeout(searchTimeout);

      if (query.length < 2) {
        searchResults.style.display = "none";
        return;
      }

      // Debounce search (300ms)
      searchTimeout = setTimeout(() => {
        performSearch(query);
      }, 300);
    });

    // Close search results when clicking elsewhere
    document.addEventListener("click", function (e) {
      if (!e.target.closest(".search-container")) {
        searchResults.style.display = "none";
      }
    });
  }

  async function performSearch(query) {
    try {
      const response = await fetch(
        `/api/search-users?q=${encodeURIComponent(query)}`
      );

      if (!response.ok) {
        console.error("Search failed:", response.status);
        return;
      }

      const data = await response.json();

      if (data.results && data.results.length > 0) {
        displaySearchResults(data.results);
      } else {
        displaySearchResults([]);
      }
    } catch (error) {
      console.error("Search error:", error);
    }
  }

  function displaySearchResults(users) {
    searchResults.innerHTML = "";

    if (users.length === 0) {
      searchResults.innerHTML =
        '<div class="search-result-item" style="text-align: center; color: #999;">No users found</div>';
    } else {
      users.forEach((user) => {
        const item = document.createElement("div");
        item.className = "search-result-item";
        item.innerHTML = `
          <div class="search-result-username">@${escapeHtml(
            user.username
          )}</div>
          <div class="search-result-fullname">${escapeHtml(user.fullname)}</div>
        `;
        item.addEventListener("click", () => {
          // Navigate to user profile or open user details
          window.location.href = `/user/${user.id}`;
        });
        searchResults.appendChild(item);
      });
    }

    searchResults.style.display = "block";
  }

  // ==================== Profile Dropdown Functionality ====================
  if (profileBtn) {
    profileBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      const isVisible = profileDropdown.style.display !== "none";
      profileDropdown.style.display = isVisible ? "none" : "block";
    });

    // Load profile picture from session/database
    loadProfilePicture();
  }

  async function loadProfilePicture() {
    try {
      const response = await fetch("/api/profile-picture");

      if (!response.ok) return;

      const data = await response.json();
      const defaultAvatar =
        "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCA0OCA0OCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNPCN jmMjQgNDggQzEwLjc0NjEgNDggMCA0Ny4yNTM5IDAgMzJDMCAyNS41NjY1IDAgMTYgMjQgMTZDMzYgMTYgNDggMjUuNTY2NSA0OCAzMkM0OCA0Ny4yNTM5IDM3LjI1MzkgNDggMjQgNDhaIiBmaWxsPSIjRTBFMEUwIi8+CjxjaXJjbGUgY3g9IjI0IiBjeT0iMTYiIHI9IjgiIGZpbGw9IiNFMEUwRTAiLz4KPC9zdmc+";

      if (data.profile_pic) {
        const picPath = `/static/profile_pics/${data.profile_pic}`;
        document.getElementById("headerProfilePic").src = picPath;
        document.getElementById("dropdownProfilePic").src = picPath;
      } else {
        document.getElementById("headerProfilePic").src = defaultAvatar;
        document.getElementById("dropdownProfilePic").src = defaultAvatar;
      }
    } catch (error) {
      console.error("Profile picture load error:", error);
      // Set default avatar on error
      const defaultAvatar =
        "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCA0OCA0OCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNPCN jmMjQgNDggQzEwLjc0NjEgNDggMCA0Ny4yNTM5IDAgMzJDMCAyNS41NjY1IDAgMTYgMjQgMTZDMzYgMTYgNDggMjUuNTY2NSA0OCAzMkM0OCA0Ny4yNTM5IDM3LjI1MzkgNDggMjQgNDhaIiBmaWxsPSIjRTBFMEUwIi8+CjxjaXJjbGUgY3g9IjI0IiBjeT0iMTYiIHI9IjgiIGZpbGw9IiNFMEUwRTAiLz4KPC9zdmc+";
      document.getElementById("headerProfilePic").src = defaultAvatar;
      document.getElementById("dropdownProfilePic").src = defaultAvatar;
    }
  }

  // ==================== Close Dropdowns on Outside Click ====================
  document.addEventListener("click", function (e) {
    if (!e.target.closest(".notification-item") && notificationDropdown) {
      notificationDropdown.style.display = "none";
    }

    if (!e.target.closest(".user-profile") && profileDropdown) {
      profileDropdown.style.display = "none";
    }
  });

  // ==================== Menu Toggle for Mobile ====================
  const menuToggle = document.getElementById("menuToggle");
  if (menuToggle) {
    menuToggle.addEventListener("click", function () {
      const sidebar = document.querySelector(".sidebar");
      if (sidebar) {
        sidebar.classList.toggle("active");
      }
    });
  }

  // ==================== Utility Functions ====================
  function escapeHtml(text) {
    const map = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
  }

  function formatTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "just now";
    if (diffMins < 60)
      return `${diffMins} minute${diffMins > 1 ? "s" : ""} ago`;
    if (diffHours < 24)
      return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;

    return date.toLocaleDateString();
  }
});
