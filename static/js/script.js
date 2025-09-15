// Custom JavaScript for Flask Task Manager

document.addEventListener("DOMContentLoaded", function () {
  // Auto-dismiss alerts after 5 seconds
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      const bsAlert = new bootstrap.Alert(alert);
      bsAlert.close();
    }, 5000);
  });

  // Enable Bootstrap tooltips
  const tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  // Enable Bootstrap popovers
  const popoverTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="popover"]')
  );
  const popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
    return new bootstrap.Popover(popoverTriggerEl);
  });

  // Form validation
  const forms = document.querySelectorAll(".needs-validation");
  forms.forEach((form) => {
    form.addEventListener(
      "submit",
      (event) => {
        if (!form.checkValidity()) {
          event.preventDefault();
          event.stopPropagation();
        }
        form.classList.add("was-validated");
      },
      false
    );
  });

  // Due date validation - ensure due date is not in the past
  const dueDateInput = document.getElementById("due_date");
  if (dueDateInput) {
    dueDateInput.addEventListener("change", function () {
      const selectedDate = new Date(this.value);
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      if (selectedDate < today) {
        alert("La date d'échéance ne peut pas être dans le passé.");
        this.value = "";
      }
    });
  }

  // Password confirmation validation
  const password = document.getElementById("password");
  const confirmPassword = document.getElementById("confirm_password");

  if (password && confirmPassword) {
    function validatePassword() {
      if (password.value !== confirmPassword.value) {
        confirmPassword.setCustomValidity(
          "Les mots de passe ne correspondent pas."
        );
      } else {
        confirmPassword.setCustomValidity("");
      }
    }

    password.addEventListener("change", validatePassword);
    confirmPassword.addEventListener("keyup", validatePassword);
  }

  // Task filter form - auto submit on change
  const statusFilter = document.getElementById("status");
  const priorityFilter = document.getElementById("priority");

  if (statusFilter) {
    statusFilter.addEventListener("change", function () {
      this.form.submit();
    });
  }

  if (priorityFilter) {
    priorityFilter.addEventListener("change", function () {
      this.form.submit();
    });
  }

  // Mark task as complete
  const completeButtons = document.querySelectorAll(".complete-task");
  completeButtons.forEach((button) => {
    button.addEventListener("click", function (e) {
      e.preventDefault();
      const taskId = this.dataset.taskId;
      if (confirm("Marquer cette tâche comme terminée ?")) {
        fetch(`/task/${taskId}/complete`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
        })
          .then((response) => response.json())
          .then((data) => {
            if (data.success) {
              location.reload();
            } else {
              alert("Erreur: " + data.message);
            }
          })
          .catch((error) => {
            console.error("Error:", error);
            alert("Une erreur s'est produite.");
          });
      }
    });
  });

  // Image preview for profile image upload
  const profileImageInput = document.getElementById("profile_image");
  const profileImagePreview = document.getElementById("profile_image_preview");

  if (profileImageInput && profileImagePreview) {
    profileImageInput.addEventListener("change", function () {
      const file = this.files[0];
      if (file) {
        const reader = new FileReader();
        reader.addEventListener("load", function () {
          profileImagePreview.setAttribute("src", this.result);
        });
        reader.readAsDataURL(file);
      }
    });
  }
});

// Utility function to format dates
function formatDate(dateString) {
  const options = { year: "numeric", month: "short", day: "numeric" };
  return new Date(dateString).toLocaleDateString("fr-FR", options);
}

// Utility function to show loading spinner
function showLoading() {
  const loadingOverlay = document.createElement("div");
  loadingOverlay.id = "loading-overlay";
  loadingOverlay.style.position = "fixed";
  loadingOverlay.style.top = "0";
  loadingOverlay.style.left = "0";
  loadingOverlay.style.width = "100%";
  loadingOverlay.style.height = "100%";
  loadingOverlay.style.backgroundColor = "rgba(255, 255, 255, 0.8)";
  loadingOverlay.style.display = "flex";
  loadingOverlay.style.justifyContent = "center";
  loadingOverlay.style.alignItems = "center";
  loadingOverlay.style.zIndex = "9999";

  const spinner = document.createElement("div");
  spinner.className = "spinner-border text-primary";
  spinner.role = "status";

  const srOnly = document.createElement("span");
  srOnly.className = "visually-hidden";
  srOnly.textContent = "Chargement...";

  spinner.appendChild(srOnly);
  loadingOverlay.appendChild(spinner);
  document.body.appendChild(loadingOverlay);
}

// Utility function to hide loading spinner
function hideLoading() {
  const loadingOverlay = document.getElementById("loading-overlay");
  if (loadingOverlay) {
    loadingOverlay.remove();
  }
}

// Add loading indicator to all forms
document.querySelectorAll("form").forEach((form) => {
  form.addEventListener("submit", () => {
    showLoading();
  });
});
