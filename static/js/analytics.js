document.addEventListener("DOMContentLoaded", function () {
  // Data will be injected by the template
  // This prevents linter errors from seeing template syntax

  // REFACTORED: Students with Allergies by Strand Chart
  if (
    window.studentsAllergiesStrandData &&
    Object.keys(window.studentsAllergiesStrandData).length > 0
  ) {
    const strandCtx = document.getElementById("studentsAllergiesStrandChart");
    if (strandCtx) {
      try {
        new Chart(strandCtx, {
          type: "bar",
          data: {
            labels: Object.keys(window.studentsAllergiesStrandData),
            datasets: [
              {
                label: "Students with Allergies",
                data: Object.values(window.studentsAllergiesStrandData),
                backgroundColor: "#FF6384",
                borderColor: "#FF6384",
                borderWidth: 1,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: "y",
            plugins: {
              legend: { position: "bottom" },
              title: {
                display: true,
                text: "Students with Allergies by Strand",
              },
            },
            scales: {
              x: {
                beginAtZero: true,
                ticks: {
                  stepSize: 1,
                },
              },
            },
          },
        });
      } catch (err) {
        console.error("Error rendering students allergies strand chart:", err);
      }
    }
  }

  // REFACTORED: Strands with Most Clinic Visits Chart
  if (
    window.strandsClinicVisitsData &&
    Object.keys(window.strandsClinicVisitsData).length > 0
  ) {
    const visitsCtx = document.getElementById("strandsClinicVisitsChart");
    if (visitsCtx) {
      try {
        new Chart(visitsCtx, {
          type: "bar",
          data: {
            labels: Object.keys(window.strandsClinicVisitsData),
            datasets: [
              {
                label: "Clinic Visits",
                data: Object.values(window.strandsClinicVisitsData),
                backgroundColor: "#36A2EB",
                borderColor: "#36A2EB",
                borderWidth: 1,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: "bottom" },
              title: {
                display: true,
                text: "Clinic Visits by Strand",
              },
            },
            scales: {
              y: {
                beginAtZero: true,
                ticks: {
                  stepSize: 1,
                },
              },
            },
          },
        });
      } catch (err) {
        console.error("Error rendering strands clinic visits chart:", err);
      }
    }
  }

  // Apply data-width values to trend bars
  document
    .querySelectorAll(".trend-bar-fill[data-width]")
    .forEach((element) => {
      const width = element.getAttribute("data-width");
      element.style.width = width + "%";
    });
});
