// Main application file for Baraka General Medical Clinic

const express = require("express");
const mysql = require("mysql2");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("connect-flash");
const methodOverride = require("method-override");

const app = express();
const PORT = 9000;

// Database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", // Update with your MySQL password
  database: "baraka_clinic",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

// Middleware
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride("_method"));

// Session configuration
app.use(
  session({
    secret: "baraka-clinic-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 }, // 1 hour
  })
);

app.use(flash());

// Global variables middleware
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.user = req.session.user || null;
  next();
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  req.flash("error_msg", "Please log in to access this page");
  res.redirect("/login");
};

// Role-based access control middleware
const checkRole = (roles) => {
  return (req, res, next) => {
    if (!req.session.user) {
      req.flash("error_msg", "Please log in to access this page");
      return res.redirect("/login");
    }

    if (roles.includes(req.session.user.role)) {
      return next();
    }

    req.flash("error_msg", "You do not have permission to access this page");
    res.redirect("/dashboard");
  };
};

// Routes

// Home route
app.get("/", (req, res) => {
  res.render("index", { title: "Baraka General Medical Clinic" });
});

// Login routes
app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }
  res.render("login", { title: "Login" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    req.flash("error_msg", "Please enter all fields");
    return res.redirect("/login");
  }

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) {
        console.error("Error querying database:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/login");
      }

      if (results.length === 0) {
        req.flash("error_msg", "Invalid username or password");
        return res.redirect("/login");
      }

      const user = results[0];

      try {
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          req.flash("error_msg", "Invalid username or password");
          return res.redirect("/login");
        }

        // Store user in session
        req.session.user = {
          id: user.id,
          username: user.username,
          role: user.role,
        };

        req.flash("success_msg", "You are now logged in");
        res.redirect("/dashboard");
      } catch (error) {
        console.error("Error comparing passwords:", error);
        req.flash("error_msg", "An error occurred. Please try again.");
        res.redirect("/login");
      }
    }
  );
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    res.redirect("/login");
  });
});

// Registration routes
app.get("/register/patient", (req, res) => {
  res.render("register-patient", { title: "Patient Registration" });
});

app.post("/register/patient", async (req, res) => {
  const {
    username,
    password,
    confirm_password,
    first_name,
    last_name,
    email,
    phone,
    address,
    date_of_birth,
    gender,
    blood_group,
  } = req.body;

  // Validation
  if (
    !username ||
    !password ||
    !confirm_password ||
    !first_name ||
    !last_name ||
    !email ||
    !phone
  ) {
    req.flash("error_msg", "Please fill in all required fields");
    return res.redirect("/register/patient");
  }

  if (password !== confirm_password) {
    req.flash("error_msg", "Passwords do not match");
    return res.redirect("/register/patient");
  }

  try {
    // Check if username already exists
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, results) => {
        if (err) {
          console.error("Error querying database:", err);
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/register/patient");
        }

        if (results.length > 0) {
          req.flash("error_msg", "Username already exists");
          return res.redirect("/register/patient");
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Begin transaction
        db.beginTransaction(async (err) => {
          if (err) {
            console.error("Error beginning transaction:", err);
            req.flash("error_msg", "An error occurred. Please try again.");
            return res.redirect("/register/patient");
          }

          // Insert user
          db.query(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [username, hashedPassword, "patient"],
            (err, result) => {
              if (err) {
                return db.rollback(() => {
                  console.error("Error inserting user:", err);
                  req.flash(
                    "error_msg",
                    "An error occurred. Please try again."
                  );
                  res.redirect("/register/patient");
                });
              }

              const userId = result.insertId;

              // Insert patient
              db.query(
                "INSERT INTO patients (user_id, first_name, last_name, email, phone, address, date_of_birth, gender, blood_group) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                  userId,
                  first_name,
                  last_name,
                  email,
                  phone,
                  address,
                  date_of_birth,
                  gender,
                  blood_group,
                ],
                (err) => {
                  if (err) {
                    return db.rollback(() => {
                      console.error("Error inserting patient:", err);
                      req.flash(
                        "error_msg",
                        "An error occurred. Please try again."
                      );
                      res.redirect("/register/patient");
                    });
                  }

                  // Commit transaction
                  db.commit((err) => {
                    if (err) {
                      return db.rollback(() => {
                        console.error("Error committing transaction:", err);
                        req.flash(
                          "error_msg",
                          "An error occurred. Please try again."
                        );
                        res.redirect("/register/patient");
                      });
                    }

                    req.flash(
                      "success_msg",
                      "You are now registered and can log in"
                    );
                    res.redirect("/login");
                  });
                }
              );
            }
          );
        });
      }
    );
  } catch (error) {
    console.error("Error in patient registration:", error);
    req.flash("error_msg", "An error occurred. Please try again.");
    res.redirect("/register/patient");
  }
});

app.get("/register/doctor", checkRole(["admin", "superadmin"]), (req, res) => {
  res.render("register-doctor", { title: "Doctor Registration" });
});

app.post(
  "/register/doctor",
  checkRole(["admin", "superadmin"]),
  async (req, res) => {
    const {
      username,
      password,
      confirm_password,
      first_name,
      last_name,
      email,
      phone,
      specialization,
      qualification,
      experience,
      salary,
    } = req.body;

    // Validation
    if (
      !username ||
      !password ||
      !confirm_password ||
      !first_name ||
      !last_name ||
      !email ||
      !phone ||
      !specialization
    ) {
      req.flash("error_msg", "Please fill in all required fields");
      return res.redirect("/register/doctor");
    }

    if (password !== confirm_password) {
      req.flash("error_msg", "Passwords do not match");
      return res.redirect("/register/doctor");
    }

    try {
      // Check if username already exists
      db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, results) => {
          if (err) {
            console.error("Error querying database:", err);
            req.flash("error_msg", "An error occurred. Please try again.");
            return res.redirect("/register/doctor");
          }

          if (results.length > 0) {
            req.flash("error_msg", "Username already exists");
            return res.redirect("/register/doctor");
          }

          // Hash password
          const hashedPassword = await bcrypt.hash(password, 10);

          // Begin transaction
          db.beginTransaction(async (err) => {
            if (err) {
              console.error("Error beginning transaction:", err);
              req.flash("error_msg", "An error occurred. Please try again.");
              return res.redirect("/register/doctor");
            }

            // Insert user
            db.query(
              "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
              [username, hashedPassword, "doctor"],
              (err, result) => {
                if (err) {
                  return db.rollback(() => {
                    console.error("Error inserting user:", err);
                    req.flash(
                      "error_msg",
                      "An error occurred. Please try again."
                    );
                    res.redirect("/register/doctor");
                  });
                }

                const userId = result.insertId;

                // Insert doctor
                db.query(
                  "INSERT INTO doctors (user_id, first_name, last_name, email, phone, specialization, qualification, experience, salary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  [
                    userId,
                    first_name,
                    last_name,
                    email,
                    phone,
                    specialization,
                    qualification,
                    experience,
                    salary,
                  ],
                  (err) => {
                    if (err) {
                      return db.rollback(() => {
                        console.error("Error inserting doctor:", err);
                        req.flash(
                          "error_msg",
                          "An error occurred. Please try again."
                        );
                        res.redirect("/register/doctor");
                      });
                    }

                    // Commit transaction
                    db.commit((err) => {
                      if (err) {
                        return db.rollback(() => {
                          console.error("Error committing transaction:", err);
                          req.flash(
                            "error_msg",
                            "An error occurred. Please try again."
                          );
                          res.redirect("/register/doctor");
                        });
                      }

                      req.flash(
                        "success_msg",
                        "Doctor registered successfully"
                      );
                      res.redirect("/doctors");
                    });
                  }
                );
              }
            );
          });
        }
      );
    } catch (error) {
      console.error("Error in doctor registration:", error);
      req.flash("error_msg", "An error occurred. Please try again.");
      res.redirect("/register/doctor");
    }
  }
);

app.get("/register/admin", checkRole(["superadmin"]), (req, res) => {
  res.render("register-admin", { title: "Admin Registration" });
});

app.post("/register/admin", checkRole(["superadmin"]), async (req, res) => {
  const {
    username,
    password,
    confirm_password,
    first_name,
    last_name,
    email,
    phone,
  } = req.body;

  // Validation
  if (
    !username ||
    !password ||
    !confirm_password ||
    !first_name ||
    !last_name ||
    !email ||
    !phone
  ) {
    req.flash("error_msg", "Please fill in all required fields");
    return res.redirect("/register/admin");
  }

  if (password !== confirm_password) {
    req.flash("error_msg", "Passwords do not match");
    return res.redirect("/register/admin");
  }

  try {
    // Check if username already exists
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, results) => {
        if (err) {
          console.error("Error querying database:", err);
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/register/admin");
        }

        if (results.length > 0) {
          req.flash("error_msg", "Username already exists");
          return res.redirect("/register/admin");
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Begin transaction
        db.beginTransaction(async (err) => {
          if (err) {
            console.error("Error beginning transaction:", err);
            req.flash("error_msg", "An error occurred. Please try again.");
            return res.redirect("/register/admin");
          }

          // Insert user
          db.query(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [username, hashedPassword, "admin"],
            (err, result) => {
              if (err) {
                return db.rollback(() => {
                  console.error("Error inserting user:", err);
                  req.flash(
                    "error_msg",
                    "An error occurred. Please try again."
                  );
                  res.redirect("/register/admin");
                });
              }

              const userId = result.insertId;

              // Insert admin
              db.query(
                "INSERT INTO admins (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
                [userId, first_name, last_name, email, phone],
                (err) => {
                  if (err) {
                    return db.rollback(() => {
                      console.error("Error inserting admin:", err);
                      req.flash(
                        "error_msg",
                        "An error occurred. Please try again."
                      );
                      res.redirect("/register/admin");
                    });
                  }

                  // Commit transaction
                  db.commit((err) => {
                    if (err) {
                      return db.rollback(() => {
                        console.error("Error committing transaction:", err);
                        req.flash(
                          "error_msg",
                          "An error occurred. Please try again."
                        );
                        res.redirect("/register/admin");
                      });
                    }

                    req.flash("success_msg", "Admin registered successfully");
                    res.redirect("/admins");
                  });
                }
              );
            }
          );
        });
      }
    );
  } catch (error) {
    console.error("Error in admin registration:", error);
    req.flash("error_msg", "An error occurred. Please try again.");
    res.redirect("/register/admin");
  }
});

// Dashboard routes
app.get("/dashboard", isAuthenticated, (req, res) => {
  const { role } = req.session.user;

  switch (role) {
    case "patient":
      res.redirect("/patient/dashboard");
      break;
    case "doctor":
      res.redirect("/doctor/dashboard");
      break;
    case "admin":
      res.redirect("/admin/dashboard");
      break;
    case "superadmin":
      res.redirect("/superadmin/dashboard");
      break;
    default:
      req.flash("error_msg", "Invalid user role");
      res.redirect("/logout");
  }
});

// Patient routes
app.get("/patient/dashboard", checkRole(["patient"]), (req, res) => {
  const userId = req.session.user.id;

  db.query(
    `SELECT p.* FROM patients p
     JOIN users u ON p.user_id = u.id
     WHERE u.id = ?`,
    [userId],
    (err, patientResults) => {
      if (err) {
        console.error("Error fetching patient data:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      if (patientResults.length === 0) {
        req.flash("error_msg", "Patient record not found");
        return res.redirect("/dashboard");
      }

      const patient = patientResults[0];

      // Get assigned doctor
      db.query(
        `SELECT d.*, a.assigned_date, a.status 
         FROM assignments a
         JOIN doctors d ON a.doctor_id = d.id
         WHERE a.patient_id = ? AND a.status = 'active'`,
        [patient.id],
        (err, doctorResults) => {
          if (err) {
            console.error("Error fetching assigned doctor:", err);
          }

          const assignedDoctor =
            doctorResults.length > 0 ? doctorResults[0] : null;

          // Get bills
          db.query(
            `SELECT * FROM bills WHERE patient_id = ? ORDER BY generated_date DESC`,
            [patient.id],
            (err, billResults) => {
              if (err) {
                console.error("Error fetching bills:", err);
              }

              res.render("patient-dashboard", {
                title: "Patient Dashboard",
                patient,
                assignedDoctor,
                bills: billResults || [],
              });
            }
          );
        }
      );
    }
  );
});

// Doctor routes
app.get("/doctor/dashboard", checkRole(["doctor"]), (req, res) => {
  const userId = req.session.user.id;

  db.query(
    `SELECT d.* FROM doctors d
     JOIN users u ON d.user_id = u.id
     WHERE u.id = ?`,
    [userId],
    (err, doctorResults) => {
      if (err) {
        console.error("Error fetching doctor data:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctor = doctorResults[0];

      // Get assigned patients
      db.query(
        `SELECT p.*, a.assigned_date, a.status 
         FROM assignments a
         JOIN patients p ON a.patient_id = p.id
         WHERE a.doctor_id = ? AND a.status = 'active'`,
        [doctor.id],
        (err, patientResults) => {
          if (err) {
            console.error("Error fetching assigned patients:", err);
          }

          res.render("doctor-dashboard", {
            title: "Doctor Dashboard",
            doctor,
            patients: patientResults || [],
          });
        }
      );
    }
  );
});

// Admin routes
app.get("/admin/dashboard", checkRole(["admin"]), (req, res) => {
  const userId = req.session.user.id;

  db.query(
    `SELECT a.* FROM admins a
     JOIN users u ON a.user_id = u.id
     WHERE u.id = ?`,
    [userId],
    (err, adminResults) => {
      if (err) {
        console.error("Error fetching admin data:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      if (adminResults.length === 0) {
        req.flash("error_msg", "Admin record not found");
        return res.redirect("/dashboard");
      }

      const admin = adminResults[0];

      // Get counts
      db.query(
        `SELECT 
          (SELECT COUNT(*) FROM patients) AS patientCount,
          (SELECT COUNT(*) FROM doctors) AS doctorCount,
          (SELECT COUNT(*) FROM assignments WHERE status = 'active') AS assignmentCount,
          (SELECT COUNT(*) FROM bills WHERE status = 'pending') AS pendingBillCount`,
        (err, countResults) => {
          if (err) {
            console.error("Error fetching counts:", err);
          }

          const counts = countResults[0] || {
            patientCount: 0,
            doctorCount: 0,
            assignmentCount: 0,
            pendingBillCount: 0,
          };

          res.render("admin-dashboard", {
            title: "Admin Dashboard",
            admin,
            counts,
          });
        }
      );
    }
  );
});

// Super Admin routes
app.get("/superadmin/dashboard", checkRole(["superadmin"]), (req, res) => {
  const userId = req.session.user.id;

  db.query(
    `SELECT s.* FROM superadmins s
     JOIN users u ON s.user_id = u.id
     WHERE u.id = ?`,
    [userId],
    (err, superadminResults) => {
      if (err) {
        console.error("Error fetching superadmin data:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      if (superadminResults.length === 0) {
        req.flash("error_msg", "Super Admin record not found");
        return res.redirect("/dashboard");
      }

      const superadmin = superadminResults[0];

      // Get counts
      db.query(
        `SELECT 
          (SELECT COUNT(*) FROM patients) AS patientCount,
          (SELECT COUNT(*) FROM doctors) AS doctorCount,
          (SELECT COUNT(*) FROM admins) AS adminCount,
          (SELECT COUNT(*) FROM bills) AS billCount`,
        (err, countResults) => {
          if (err) {
            console.error("Error fetching counts:", err);
          }

          const counts = countResults[0] || {
            patientCount: 0,
            doctorCount: 0,
            adminCount: 0,
            billCount: 0,
          };

          res.render("superadmin-dashboard", {
            title: "Super Admin Dashboard",
            superadmin,
            counts,
          });
        }
      );
    }
  );
});

// Patients management
app.get("/patients", checkRole(["admin", "superadmin"]), (req, res) => {
  db.query(
    "SELECT * FROM patients ORDER BY created_at DESC",
    (err, results) => {
      if (err) {
        console.error("Error fetching patients:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      res.render("patients", {
        title: "Patients Management",
        patients: results,
      });
    }
  );
});

app.get(
  "/patients/:id",
  checkRole(["admin", "superadmin", "doctor"]),
  (req, res) => {
    const patientId = req.params.id;

    db.query(
      "SELECT * FROM patients WHERE id = ?",
      [patientId],
      (err, patientResults) => {
        if (err) {
          console.error("Error fetching patient:", err);
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/patients");
        }

        if (patientResults.length === 0) {
          req.flash("error_msg", "Patient not found");
          return res.redirect("/patients");
        }

        const patient = patientResults[0];

        // Get assigned doctor
        db.query(
          `SELECT d.*, a.assigned_date, a.status 
       FROM assignments a
       JOIN doctors d ON a.doctor_id = d.id
       WHERE a.patient_id = ? AND a.status = 'active'`,
          [patientId],
          (err, doctorResults) => {
            if (err) {
              console.error("Error fetching assigned doctor:", err);
            }

            const assignedDoctor =
              doctorResults.length > 0 ? doctorResults[0] : null;

            // Get bills
            db.query(
              `SELECT * FROM bills WHERE patient_id = ? ORDER BY generated_date DESC`,
              [patientId],
              (err, billResults) => {
                if (err) {
                  console.error("Error fetching bills:", err);
                }

                res.render("patient-details", {
                  title: "Patient Details",
                  patient,
                  assignedDoctor,
                  bills: billResults || [],
                });
              }
            );
          }
        );
      }
    );
  }
);

// Doctors management
app.get("/doctors", checkRole(["admin", "superadmin"]), (req, res) => {
  db.query("SELECT * FROM doctors ORDER BY created_at DESC", (err, results) => {
    if (err) {
      console.error("Error fetching doctors:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }

    res.render("doctors", {
      title: "Doctors Management",
      doctors: results,
    });
  });
});

app.get("/doctors/:id", checkRole(["admin", "superadmin"]), (req, res) => {
  const doctorId = req.params.id;

  db.query(
    "SELECT * FROM doctors WHERE id = ?",
    [doctorId],
    (err, doctorResults) => {
      if (err) {
        console.error("Error fetching doctor:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/doctors");
      }

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor not found");
        return res.redirect("/doctors");
      }

      const doctor = doctorResults[0];

      // Get assigned patients
      db.query(
        `SELECT p.*, a.assigned_date, a.status 
       FROM assignments a
       JOIN patients p ON a.patient_id = p.id
       WHERE a.doctor_id = ? AND a.status = 'active'`,
        [doctorId],
        (err, patientResults) => {
          if (err) {
            console.error("Error fetching assigned patients:", err);
          }

          res.render("doctor-details", {
            title: "Doctor Details",
            doctor,
            patients: patientResults || [],
          });
        }
      );
    }
  );
});

// Update doctor
app.post("/doctors/:id", checkRole(["admin", "superadmin"]), (req, res) => {
  const doctorId = req.params.id;
  const {
    first_name,
    last_name,
    email,
    phone,
    specialization,
    qualification,
    experience,
    salary,
  } = req.body;

  db.query(
    `UPDATE doctors SET 
     first_name = ?, 
     last_name = ?, 
     email = ?, 
     phone = ?, 
     specialization = ?, 
     qualification = ?, 
     experience = ?, 
     salary = ? 
     WHERE id = ?`,
    [
      first_name,
      last_name,
      email,
      phone,
      specialization,
      qualification,
      experience,
      salary,
      doctorId,
    ],
    (err) => {
      if (err) {
        console.error("Error updating doctor:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect(`/doctors/${doctorId}`);
      }

      req.flash("success_msg", "Doctor updated successfully");
      res.redirect(`/doctors/${doctorId}`);
    }
  );
});

// Delete doctor
app.delete("/doctors/:id", checkRole(["admin", "superadmin"]), (req, res) => {
  const doctorId = req.params.id;

  db.query(
    "SELECT user_id FROM doctors WHERE id = ?",
    [doctorId],
    (err, results) => {
      if (err) {
        console.error("Error fetching doctor user_id:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/doctors");
      }

      if (results.length === 0) {
        req.flash("error_msg", "Doctor not found");
        return res.redirect("/doctors");
      }

      const userId = results[0].user_id;

      // Begin transaction
      db.beginTransaction((err) => {
        if (err) {
          console.error("Error beginning transaction:", err);
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/doctors");
        }

        // Delete doctor
        db.query("DELETE FROM doctors WHERE id = ?", [doctorId], (err) => {
          if (err) {
            return db.rollback(() => {
              console.error("Error deleting doctor:", err);
              req.flash("error_msg", "An error occurred. Please try again.");
              res.redirect("/doctors");
            });
          }

          // Delete user
          db.query("DELETE FROM users WHERE id = ?", [userId], (err) => {
            if (err) {
              return db.rollback(() => {
                console.error("Error deleting user:", err);
                req.flash("error_msg", "An error occurred. Please try again.");
                res.redirect("/doctors");
              });
            }

            // Commit transaction
            db.commit((err) => {
              if (err) {
                return db.rollback(() => {
                  console.error("Error committing transaction:", err);
                  req.flash(
                    "error_msg",
                    "An error occurred. Please try again."
                  );
                  res.redirect("/doctors");
                });
              }

              req.flash("success_msg", "Doctor deleted successfully");
              res.redirect("/doctors");
            });
          });
        });
      });
    }
  );
});

// Admins management
app.get("/admins", checkRole(["superadmin"]), (req, res) => {
  db.query("SELECT * FROM admins ORDER BY created_at DESC", (err, results) => {
    if (err) {
      console.error("Error fetching admins:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }

    res.render("admins", {
      title: "Admins Management",
      admins: results,
    });
  });
});

// Delete admin
app.delete("/admins/:id", checkRole(["superadmin"]), (req, res) => {
  const adminId = req.params.id;

  db.query(
    "SELECT user_id FROM admins WHERE id = ?",
    [adminId],
    (err, results) => {
      if (err) {
        console.error("Error fetching admin user_id:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/admins");
      }

      if (results.length === 0) {
        req.flash("error_msg", "Admin not found");
        return res.redirect("/admins");
      }

      const userId = results[0].user_id;

      // Begin transaction
      db.beginTransaction((err) => {
        if (err) {
          console.error("Error beginning transaction:", err);
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/admins");
        }

        // Delete admin
        db.query("DELETE FROM admins WHERE id = ?", [adminId], (err) => {
          if (err) {
            return db.rollback(() => {
              console.error("Error deleting admin:", err);
              req.flash("error_msg", "An error occurred. Please try again.");
              res.redirect("/admins");
            });
          }

          // Delete user
          db.query("DELETE FROM users WHERE id = ?", [userId], (err) => {
            if (err) {
              return db.rollback(() => {
                console.error("Error deleting user:", err);
                req.flash("error_msg", "An error occurred. Please try again.");
                res.redirect("/admins");
              });
            }

            // Commit transaction
            db.commit((err) => {
              if (err) {
                return db.rollback(() => {
                  console.error("Error committing transaction:", err);
                  req.flash(
                    "error_msg",
                    "An error occurred. Please try again."
                  );
                  res.redirect("/admins");
                });
              }

              req.flash("success_msg", "Admin deleted successfully");
              res.redirect("/admins");
            });
          });
        });
      });
    }
  );
});

// Assignments management
app.get("/assignments", checkRole(["admin", "superadmin"]), (req, res) => {
  db.query(
    `SELECT a.*, p.first_name AS patient_first_name, p.last_name AS patient_last_name,
     d.first_name AS doctor_first_name, d.last_name AS doctor_last_name
     FROM assignments a
     JOIN patients p ON a.patient_id = p.id
     JOIN doctors d ON a.doctor_id = d.id
     ORDER BY a.assigned_date DESC`,
    (err, results) => {
      if (err) {
        console.error("Error fetching assignments:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      res.render("assignments", {
        title: "Assignments Management",
        assignments: results,
      });
    }
  );
});

app.get("/assignments/new", checkRole(["admin", "superadmin"]), (req, res) => {
  // Get patients
  db.query(
    "SELECT id, first_name, last_name FROM patients",
    (err, patientResults) => {
      if (err) {
        console.error("Error fetching patients:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/assignments");
      }

      // Get doctors
      db.query(
        "SELECT id, first_name, last_name, specialization FROM doctors",
        (err, doctorResults) => {
          if (err) {
            console.error("Error fetching doctors:", err);
            req.flash("error_msg", "An error occurred. Please try again.");
            return res.redirect("/assignments");
          }

          res.render("assignment-new", {
            title: "New Assignment",
            patients: patientResults,
            doctors: doctorResults,
          });
        }
      );
    }
  );
});

app.post("/assignments", checkRole(["admin", "superadmin"]), (req, res) => {
  const { patient_id, doctor_id, notes } = req.body;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;

  // Check if patient already has an active assignment
  db.query(
    'SELECT * FROM assignments WHERE patient_id = ? AND status = "active"',
    [patient_id],
    (err, results) => {
      if (err) {
        console.error("Error checking existing assignments:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/assignments/new");
      }

      if (results.length > 0) {
        req.flash("error_msg", "Patient already has an active assignment");
        return res.redirect("/assignments/new");
      }

      // Get the appropriate ID based on user role
      if (userRole === "admin") {
        db.query(
          "SELECT id FROM admins WHERE user_id = ?",
          [userId],
          (err, results) => {
            if (err || results.length === 0) {
              console.error("Error fetching admin ID:", err);
              req.flash("error_msg", "Admin record not found");
              return res.redirect("/assignments/new");
            }

            const adminId = results[0].id;
            // Create assignment with admin ID
            createAssignment(adminId, "admin");
          }
        );
      } else if (userRole === "superadmin") {
        // For superadmin, we'll use NULL for assigned_by since it's not in the admins table
        createAssignment(null, "superadmin");
      }
    }
  );

  // Helper function to create the assignment
  function createAssignment(assignedById, creatorType) {
    // Create assignment
    db.query(
      "INSERT INTO assignments (patient_id, doctor_id, assigned_by, creator_type, notes) VALUES (?, ?, ?, ?, ?)",
      [patient_id, doctor_id, assignedById, creatorType, notes],
      (err) => {
        if (err) {
          console.error("Error creating assignment:", err, {
            patient_id,
            doctor_id,
            assignedById,
            creatorType,
            notes,
          });
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/assignments/new");
        }

        req.flash("success_msg", "Assignment created successfully");
        res.redirect("/assignments");
      }
    );
  }
});

app.put("/assignments/:id", checkRole(["admin", "superadmin"]), (req, res) => {
  const assignmentId = req.params.id;
  const { status, notes } = req.body;

  db.query(
    "UPDATE assignments SET status = ?, notes = ? WHERE id = ?",
    [status, notes, assignmentId],
    (err) => {
      if (err) {
        console.error("Error updating assignment:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/assignments");
      }

      req.flash("success_msg", "Assignment updated successfully");
      res.redirect("/assignments");
    }
  );
});

// Bills management
app.get("/bills", checkRole(["admin", "superadmin"]), (req, res) => {
  db.query(
    `SELECT b.*, p.first_name AS patient_first_name, p.last_name AS patient_last_name
     FROM bills b
     JOIN patients p ON b.patient_id = p.id
     ORDER BY b.generated_date DESC`,
    (err, results) => {
      if (err) {
        console.error("Error fetching bills:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/dashboard");
      }

      res.render("bills", {
        title: "Bills Management",
        bills: results,
      });
    }
  );
});

app.get("/bills/new", checkRole(["admin", "superadmin"]), (req, res) => {
  // Get patients
  db.query(
    "SELECT id, first_name, last_name FROM patients",
    (err, patientResults) => {
      if (err) {
        console.error("Error fetching patients:", err);
        req.flash("error_msg", "An error occurred. Please try again.");
        return res.redirect("/bills");
      }

      res.render("bill-new", {
        title: "New Bill",
        patients: patientResults,
      });
    }
  );
});

app.post("/bills", checkRole(["admin", "superadmin"]), (req, res) => {
  const { patient_id, amount, description } = req.body;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;

  // Get the appropriate ID based on user role
  if (userRole === "admin") {
    db.query(
      "SELECT id FROM admins WHERE user_id = ?",
      [userId],
      (err, results) => {
        if (err || results.length === 0) {
          console.error("Error fetching admin ID:", err);
          req.flash("error_msg", "Admin record not found");
          return res.redirect("/bills/new");
        }

        const adminId = results[0].id;
        // Create bill with admin ID
        createBill(adminId);
      }
    );
  } else if (userRole === "superadmin") {
    // For superadmin, we'll use NULL for generated_by since it's not in the admins table
    createBill(null);
  }

  // Helper function to create the bill
  function createBill(generatedById) {
    // Create bill
    db.query(
      "INSERT INTO bills (patient_id, amount, description, generated_by) VALUES (?, ?, ?, ?)",
      [patient_id, amount, description, generatedById],
      (err) => {
        if (err) {
          console.error("Error creating bill:", err);
          req.flash("error_msg", "An error occurred. Please try again.");
          return res.redirect("/bills/new");
        }

        req.flash("success_msg", "Bill created successfully");
        res.redirect("/bills");
      }
    );
  }
});

app.put("/bills/:id", checkRole(["admin", "superadmin"]), (req, res) => {
  const billId = req.params.id;
  const { status } = req.body;

  const updateData = {
    status,
  };

  // If status is 'paid', set payment date
  if (status === "paid") {
    updateData.payment_date = new Date();
  }

  db.query("UPDATE bills SET ? WHERE id = ?", [updateData, billId], (err) => {
    if (err) {
      console.error("Error updating bill:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/bills");
    }

    req.flash("success_msg", "Bill updated successfully");
    res.redirect("/bills");
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
