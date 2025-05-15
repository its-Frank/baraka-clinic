const express = require("express");
const mysql = require("mysql2/promise");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("connect-flash");
const methodOverride = require("method-override");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 9000;

// Database connection pool
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "baraka_clinic",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log("Connected to MySQL database");
    connection.release();
  } catch (err) {
    console.error("Error connecting to MySQL:", err);
  }
}

testConnection();

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
    secret: process.env.SESSION_SECRET || "baraka-clinic-secret-key",
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
  const role = req.query.role || "patient";
  res.render("login", { title: "Login", role });
});

app.post("/login", async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    req.flash("error_msg", "Please enter all fields");
    return res.redirect("/login");
  }

  try {
    const [users] = await pool.query(
      "SELECT * FROM users WHERE username = ? AND role = ?",
      [username, role || "patient"]
    );

    if (users.length === 0) {
      req.flash("error_msg", "Invalid username or password");
      return res.redirect("/login");
    }

    const user = users[0];
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
    console.error("Error during login:", error);
    req.flash("error_msg", "An error occurred. Please try again.");
    res.redirect("/login");
  }
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
    const [existingUsers] = await pool.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (existingUsers.length > 0) {
      req.flash("error_msg", "Username already exists");
      return res.redirect("/register/patient");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Begin transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Insert user
      const [userResult] = await connection.query(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [username, hashedPassword, "patient"]
      );

      const userId = userResult.insertId;

      // Insert patient
      await connection.query(
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
        ]
      );

      // Commit transaction
      await connection.commit();
      connection.release();

      req.flash("success_msg", "You are now registered and can log in");
      res.redirect("/login");
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error("Error in patient registration:", error);
    req.flash("error_msg", "An error occurred. Please try again.");
    res.redirect("/register/patient");
  }
});

app.get(
  "/register/doctor",
  checkRole(["employee", "managing_director"]),
  (req, res) => {
    res.render("register-doctor", { title: "Doctor Registration" });
  }
);

app.post(
  "/register/doctor",
  checkRole(["employee", "managing_director"]),
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
      const [existingUsers] = await pool.query(
        "SELECT * FROM users WHERE username = ?",
        [username]
      );

      if (existingUsers.length > 0) {
        req.flash("error_msg", "Username already exists");
        return res.redirect("/register/doctor");
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Begin transaction
      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // Insert user
        const [userResult] = await connection.query(
          "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
          [username, hashedPassword, "doctor"]
        );

        const userId = userResult.insertId;

        // Insert doctor
        await connection.query(
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
          ]
        );

        // Commit transaction
        await connection.commit();
        connection.release();

        req.flash("success_msg", "Doctor registered successfully");
        res.redirect("/doctors");
      } catch (error) {
        await connection.rollback();
        connection.release();
        throw error;
      }
    } catch (error) {
      console.error("Error in doctor registration:", error);
      req.flash("error_msg", "An error occurred. Please try again.");
      res.redirect("/register/doctor");
    }
  }
);

app.get("/register/employee", checkRole(["managing_director"]), (req, res) => {
  res.render("register-employee", { title: "Employee Registration" });
});

app.post(
  "/register/employee",
  checkRole(["managing_director"]),
  async (req, res) => {
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
      return res.redirect("/register/employee");
    }

    if (password !== confirm_password) {
      req.flash("error_msg", "Passwords do not match");
      return res.redirect("/register/employee");
    }

    try {
      // Check if username already exists
      const [existingUsers] = await pool.query(
        "SELECT * FROM users WHERE username = ?",
        [username]
      );

      if (existingUsers.length > 0) {
        req.flash("error_msg", "Username already exists");
        return res.redirect("/register/employee");
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Begin transaction
      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // Insert user
        const [userResult] = await connection.query(
          "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
          [username, hashedPassword, "employee"]
        );

        const userId = userResult.insertId;

        // Insert employee
        await connection.query(
          "INSERT INTO employees (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
          [userId, first_name, last_name, email, phone]
        );

        // Commit transaction
        await connection.commit();
        connection.release();

        req.flash("success_msg", "Employee registered successfully");
        res.redirect("/employees");
      } catch (error) {
        await connection.rollback();
        connection.release();
        throw error;
      }
    } catch (error) {
      console.error("Error in employee registration:", error);
      req.flash("error_msg", "An error occurred. Please try again.");
      res.redirect("/register/employee");
    }
  }
);

//start
// Define allowedRoles at the top level
const allowedRoles = ["patient", "doctor", "employee", "managing_director"];

// Register route
app.get("/register", (req, res) => {
  res.render("register", { title: "Register", allowedRoles });
});

app.post("/register", async (req, res) => {
  const {
    role,
    username,
    email,
    password,
    confirm_password,
    first_name,
    last_name,
    phone,
    address,
    date_of_birth,
    gender,
    blood_group,
    medical_history,
    specialization,
    qualification,
    experience,
    salary,
  } = req.body;

  // Validate role
  if (!allowedRoles.includes(role)) {
    req.flash("error_msg", "Selected role is not allowed for registration");
    return res.redirect("/register");
  }

  // Validate password match
  if (password !== confirm_password) {
    req.flash("error_msg", "Passwords do not match");
    return res.redirect("/register");
  }

  // Validate required fields
  if (!username || !email || !password || !first_name || !last_name || !phone) {
    req.flash("error_msg", "Please fill in all required fields");
    return res.redirect("/register");
  }

  if (role === "doctor") {
    if (!specialization || !qualification || !experience || !salary) {
      req.flash("error_msg", "Please fill in all required doctor fields");
      return res.redirect("/register");
    }
    if (isNaN(experience) || experience < 0) {
      req.flash("error_msg", "Experience must be a valid number");
      return res.redirect("/register");
    }
    if (isNaN(salary) || salary < 0) {
      req.flash("error_msg", "Salary must be a valid number");
      return res.redirect("/register");
    }
  }

  try {
    // Check for existing username
    const [existingUser] = await pool.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    if (existingUser.length > 0) {
      req.flash("error_msg", "Username already exists");
      return res.redirect("/register");
    }

    // Check for existing email in the appropriate role-specific table
    let emailTable;
    switch (role) {
      case "patient":
        emailTable = "patients";
        break;
      case "doctor":
        emailTable = "doctors";
        break;
      case "employee":
        emailTable = "employees";
        break;
      case "managing_director":
        emailTable = "managing_directors";
        break;
      default:
        throw new Error("Invalid role");
    }
    const [existingEmail] = await pool.query(
      `SELECT * FROM ${emailTable} WHERE email = ?`,
      [email]
    );
    if (existingEmail.length > 0) {
      req.flash("error_msg", "Email already exists");
      return res.redirect("/register");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Insert into users table
      const [userResult] = await connection.query(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [username, hashedPassword, role]
      );
      const userId = userResult.insertId;

      // Insert into role-specific table
      if (role === "patient") {
        await connection.query(
          "INSERT INTO patients (user_id, first_name, last_name, email, phone, address, date_of_birth, gender, blood_group, medical_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            medical_history,
          ]
        );
      } else if (role === "doctor") {
        await connection.query(
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
          ]
        );
      } else if (role === "employee") {
        await connection.query(
          "INSERT INTO employees (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
          [userId, first_name, last_name, email, phone]
        );
      } else if (role === "managing_director") {
        await connection.query(
          "INSERT INTO managing_directors (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
          [userId, first_name, last_name, email, phone]
        );
      }

      // Commit transaction
      await connection.commit();
      req.flash("success_msg", "Registration successful! Please login.");
      res.redirect("/login");
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error(err);
    req.flash("error_msg", "Registration failed. Please try again.");
    res.redirect("/register");
  }
});

//end

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
    case "employee":
      res.redirect("/employee/dashboard");
      break;
    case "managing_director":
      res.redirect("/managing-director/dashboard");
      break;
    default:
      req.flash("error_msg", "Invalid user role");
      res.redirect("/logout");
  }
});

// Patient routes
app.get("/patient/dashboard", checkRole(["patient"]), async (req, res) => {
  const userId = req.session.user.id;

  try {
    const [patientResults] = await pool.query(
      `SELECT p.* FROM patients p
       JOIN users u ON p.user_id = u.id
       WHERE u.id = ?`,
      [userId]
    );

    if (patientResults.length === 0) {
      req.flash("error_msg", "Patient record not found");
      return res.redirect("/dashboard");
    }

    const patient = patientResults[0];

    // Get assigned doctors
    const [doctors] = await pool.query(
      `SELECT d.*, a.assigned_date, a.status 
       FROM assignments a
       JOIN doctors d ON a.doctor_id = d.id
       WHERE a.patient_id = ? AND a.status = 'active'`,
      [patient.id]
    );

    // Get consultations
    const [consultations] = await pool.query(
      `SELECT c.*, CONCAT(d.first_name, ' ', d.last_name) as doctor_name
       FROM consultations c
       JOIN doctors d ON c.doctor_id = d.id
       WHERE c.patient_id = ?
       ORDER BY c.consultation_date DESC
       LIMIT 5`,
      [patient.id]
    );

    // Get lab tests
    const [labTests] = await pool.query(
      `SELECT pt.*, lt.name as test_name
       FROM patient_lab_tests pt
       JOIN lab_tests lt ON pt.lab_test_id = lt.id
       WHERE pt.patient_id = ?
       ORDER BY pt.requested_date DESC
       LIMIT 5`,
      [patient.id]
    );

    // Get bills
    const [bills] = await pool.query(
      `SELECT * FROM bills WHERE patient_id = ? ORDER BY generated_date DESC`,
      [patient.id]
    );

    res.render("patient-dashboard", {
      title: "Patient Dashboard",
      patient,
      doctors, // Pass the doctors array instead of assignedDoctor
      consultations,
      labTests,
      bills,
    });
  } catch (err) {
    console.error("Error fetching patient data:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/dashboard");
  }
});

// Doctor routes
app.get("/doctor/dashboard", checkRole(["doctor"]), async (req, res) => {
  const userId = req.session.user.id;

  try {
    const [doctorResults] = await pool.query(
      `SELECT d.* FROM doctors d
       JOIN users u ON d.user_id = u.id
       WHERE u.id = ?`,
      [userId]
    );

    if (doctorResults.length === 0) {
      req.flash("error_msg", "Doctor record not found");
      return res.redirect("/dashboard");
    }

    const doctor = doctorResults[0];

    // Get statistics
    const stats = {
      patientCount: 0,
      consultationCount: 0,
      labTestCount: 0,
      billCount: 0,
    };

    // Get patient count
    const [patientCountResult] = await pool.query(
      `SELECT COUNT(DISTINCT patient_id) as count 
       FROM assignments 
       WHERE doctor_id = ? AND status = 'active'`,
      [doctor.id]
    );
    stats.patientCount = patientCountResult[0].count;

    // Get consultation count
    const [consultationCountResult] = await pool.query(
      `SELECT COUNT(*) as count 
       FROM consultations 
       WHERE doctor_id = ?`,
      [doctor.id]
    );
    stats.consultationCount = consultationCountResult[0].count;

    // Get lab test count
    const [labTestCountResult] = await pool.query(
      `SELECT COUNT(*) as count 
       FROM patient_lab_tests pt
       WHERE pt.requested_by = ? AND pt.requester_type = 'doctor'`,
      [doctor.id]
    );
    stats.labTestCount = labTestCountResult[0].count;

    // Get bill count
    const [billCountResult] = await pool.query(
      `SELECT COUNT(*) as count 
       FROM bills
       WHERE generated_by = ? AND generated_by_type = 'doctor'`,
      [doctor.id]
    );
    stats.billCount = billCountResult[0].count;

    // Get recent consultations
    const [recentConsultations] = await pool.query(
      `SELECT c.*, CONCAT(p.first_name, ' ', p.last_name) as patient_name
       FROM consultations c
       JOIN patients p ON c.patient_id = p.id
       WHERE c.doctor_id = ?
       ORDER BY c.consultation_date DESC
       LIMIT 5`,
      [doctor.id]
    );

    // Get assigned patients
    const [patients] = await pool.query(
      `SELECT p.*, a.assigned_date, a.status
       FROM patients p
       JOIN assignments a ON p.id = a.patient_id
       WHERE a.doctor_id = ? AND a.status = 'active'
       ORDER BY p.first_name, p.last_name`,
      [doctor.id]
    );

    res.render("doctor-dashboard", {
      title: "Doctor Dashboard",
      doctor,
      stats,
      recentConsultations,
      patients, // Add patients to the render data
    });
  } catch (err) {
    console.error("Error fetching doctor data:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/dashboard");
  }
});

// Employee routes
app.get("/employee/dashboard", checkRole(["employee"]), async (req, res) => {
  const userId = req.session.user.id;

  try {
    const [employeeResults] = await pool.query(
      `SELECT a.* FROM employees a
       JOIN users u ON a.user_id = u.id
       WHERE u.id = ?`,
      [userId]
    );

    if (employeeResults.length === 0) {
      req.flash("error_msg", "Employee record not found");
      return res.redirect("/dashboard");
    }

    const employee = employeeResults[0];

    // Get counts
    const [countResults] = await pool.query(
      `SELECT 
          (SELECT COUNT(*) FROM patients) AS patientCount,
          (SELECT COUNT(*) FROM doctors) AS doctorCount,
          (SELECT COUNT(*) FROM assignments WHERE status = 'active') AS assignmentCount,
          (SELECT COUNT(*) FROM bills WHERE status = 'pending') AS pendingBillCount`
    );

    const counts = countResults[0] || {
      patientCount: 0,
      doctorCount: 0,
      assignmentCount: 0,
      pendingBillCount: 0,
    };

    res.render("employee-dashboard", {
      title: "Employee Dashboard",
      employee,
      counts,
    });
  } catch (err) {
    console.error("Error fetching employee data:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/dashboard");
  }
});

// Managing Director routes
app.get(
  "/managing-director/dashboard",
  checkRole(["managing_director"]),
  async (req, res) => {
    const userId = req.session.user.id;

    try {
      const [directorResults] = await pool.query(
        `SELECT s.* FROM managing_directors s
       JOIN users u ON s.user_id = u.id
       WHERE u.id = ?`,
        [userId]
      );

      if (directorResults.length === 0) {
        req.flash("error_msg", "Managing Director record not found");
        return res.redirect("/dashboard");
      }

      const managing_director = directorResults[0];

      // Get counts
      const [countResults] = await pool.query(
        `SELECT 
          (SELECT COUNT(*) FROM patients) AS patientCount,
          (SELECT COUNT(*) FROM doctors) AS doctorCount,
          (SELECT COUNT(*) FROM employees) AS employeeCount,
          (SELECT COUNT(*) FROM bills) AS billCount`
      );

      const counts = countResults[0] || {
        patientCount: 0,
        doctorCount: 0,
        employeeCount: 0,
        billCount: 0,
      };

      res.render("managing-director-dashboard", {
        title: "Managing Director Dashboard",
        managing_director,
        counts,
      });
    } catch (err) {
      console.error("Error fetching managing director data:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }
  }
);

// Patients management
app.get(
  "/patients",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    try {
      const [results] = await pool.query(
        "SELECT * FROM patients ORDER BY created_at DESC"
      );

      res.render("patients", {
        title: "Patients Management",
        patients: results,
      });
    } catch (err) {
      console.error("Error fetching patients:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }
  }
);

app.get(
  "/patients/:id",
  checkRole(["employee", "managing_director", "doctor"]),
  async (req, res) => {
    const patientId = req.params.id;

    try {
      const [patientResults] = await pool.query(
        "SELECT * FROM patients WHERE id = ?",
        [patientId]
      );

      if (patientResults.length === 0) {
        req.flash("error_msg", "Patient not found");
        return res.redirect("/patients");
      }

      const patient = patientResults[0];

      // Get assigned doctor
      const [doctorResults] = await pool.query(
        `SELECT d.*, a.assigned_date, a.status 
         FROM assignments a
         JOIN doctors d ON a.doctor_id = d.id
         WHERE a.patient_id = ? AND a.status = 'active'`,
        [patientId]
      );

      const assignedDoctor = doctorResults.length > 0 ? doctorResults[0] : null;

      // Get consultations
      const [consultations] = await pool.query(
        `SELECT c.*, CONCAT(d.first_name, ' ', d.last_name) as doctor_name
         FROM consultations c
         JOIN doctors d ON c.doctor_id = d.id
         WHERE c.patient_id = ?
         ORDER BY c.consultation_date DESC`,
        [patientId]
      );

      // Get lab tests
      const [labTests] = await pool.query(
        `SELECT pt.*, lt.name as test_name
         FROM patient_lab_tests pt
         JOIN lab_tests lt ON pt.lab_test_id = lt.id
         WHERE pt.patient_id = ?
         ORDER BY pt.requested_date DESC`,
        [patientId]
      );

      // Get bills
      const [bills] = await pool.query(
        `SELECT * FROM bills WHERE patient_id = ? ORDER BY generated_date DESC`,
        [patientId]
      );

      res.render("patient-details", {
        title: "Patient Details",
        patient,
        assignedDoctor,
        consultations,
        labTests,
        bills,
      });
    } catch (err) {
      console.error("Error fetching patient details:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/patients");
    }
  }
);

// Doctors management
app.get(
  "/doctors",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    try {
      const [results] = await pool.query(
        "SELECT * FROM doctors ORDER BY created_at DESC"
      );

      res.render("doctors", {
        title: "Doctors Management",
        doctors: results,
      });
    } catch (err) {
      console.error("Error fetching doctors:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }
  }
);

app.get(
  "/doctors/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const doctorId = req.params.id;

    try {
      const [doctorResults] = await pool.query(
        "SELECT * FROM doctors WHERE id = ?",
        [doctorId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor not found");
        return res.redirect("/doctors");
      }

      const doctor = doctorResults[0];

      // Get assigned patients
      const [patientResults] = await pool.query(
        `SELECT p.*, a.assigned_date, a.status 
       FROM assignments a
       JOIN patients p ON a.patient_id = p.id
       WHERE a.doctor_id = ? AND a.status = 'active'`,
        [doctorId]
      );

      // Get consultations
      const [consultations] = await pool.query(
        `SELECT c.*, CONCAT(p.first_name, ' ', p.last_name) as patient_name
       FROM consultations c
       JOIN patients p ON c.patient_id = p.id
       WHERE c.doctor_id = ?
       ORDER BY c.consultation_date DESC
       LIMIT 10`,
        [doctorId]
      );

      res.render("doctor-details", {
        title: "Doctor Details",
        doctor,
        patients: patientResults || [],
        consultations: consultations || [],
      });
    } catch (err) {
      console.error("Error fetching doctor details:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctors");
    }
  }
);

// Update doctor
app.post(
  "/doctors/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
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

    try {
      await pool.query(
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
        ]
      );

      req.flash("success_msg", "Doctor updated successfully");
      res.redirect(`/doctors/${doctorId}`);
    } catch (err) {
      console.error("Error updating doctor:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect(`/doctors/${doctorId}`);
    }
  }
);

// Delete doctor
app.delete(
  "/doctors/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const doctorId = req.params.id;

    try {
      const [results] = await pool.query(
        "SELECT user_id FROM doctors WHERE id = ?",
        [doctorId]
      );

      if (results.length === 0) {
        req.flash("error_msg", "Doctor not found");
        return res.redirect("/doctors");
      }

      const userId = results[0].user_id;

      // Begin transaction
      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // Delete doctor
        await connection.query("DELETE FROM doctors WHERE id = ?", [doctorId]);

        // Delete user
        await connection.query("DELETE FROM users WHERE id = ?", [userId]);

        // Commit transaction
        await connection.commit();
        connection.release();

        req.flash("success_msg", "Doctor deleted successfully");
        res.redirect("/doctors");
      } catch (error) {
        await connection.rollback();
        connection.release();
        throw error;
      }
    } catch (err) {
      console.error("Error deleting doctor:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctors");
    }
  }
);

// Employees management
app.get("/employees", checkRole(["managing_director"]), async (req, res) => {
  try {
    const [results] = await pool.query(
      "SELECT * FROM employees ORDER BY created_at DESC"
    );

    res.render("employees", {
      title: "Employees Management",
      employees: results,
    });
  } catch (err) {
    console.error("Error fetching employees:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/dashboard");
  }
});

// Delete employee
app.delete(
  "/employees/:id",
  checkRole(["managing_director"]),
  async (req, res) => {
    const employeeId = req.params.id;

    try {
      const [results] = await pool.query(
        "SELECT user_id FROM employees WHERE id = ?",
        [employeeId]
      );

      if (results.length === 0) {
        req.flash("error_msg", "Employee not found");
        return res.redirect("/employees");
      }

      const userId = results[0].user_id;

      // Begin transaction
      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // Delete employee
        await connection.query("DELETE FROM employees WHERE id = ?", [
          employeeId,
        ]);

        // Delete user
        await connection.query("DELETE FROM users WHERE id = ?", [userId]);

        // Commit transaction
        await connection.commit();
        connection.release();

        req.flash("success_msg", "Employee deleted successfully");
        res.redirect("/employees");
      } catch (error) {
        await connection.rollback();
        connection.release();
        throw error;
      }
    } catch (err) {
      console.error("Error deleting employee:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/employees");
    }
  }
);

// Assignments management
app.get(
  "/assignments",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    try {
      const [assignments] = await pool.query(`
      SELECT a.*, 
             CONCAT(p.first_name, ' ', p.last_name) as patient_name,
             CONCAT(d.first_name, ' ', d.last_name) as doctor_name,
             CONCAT(e.first_name, ' ', e.last_name) as assigned_by_name
      FROM assignments a
      JOIN patients p ON a.patient_id = p.id
      JOIN doctors d ON a.doctor_id = d.id
      LEFT JOIN employees e ON a.assigned_by = e.id
      ORDER BY a.assigned_date DESC
    `);

      res.render("assignments", {
        title: "Assignments Management",
        assignments,
      });
    } catch (err) {
      console.error("Error fetching assignments:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }
  }
);

app.get(
  "/assignments/new",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    try {
      const [patients] = await pool.query(
        "SELECT id, first_name, last_name FROM patients"
      );
      const [doctors] = await pool.query(
        "SELECT id, first_name, last_name, specialization FROM doctors"
      );

      res.render("assignment-new", {
        title: "New Assignment",
        patients,
        doctors,
      });
    } catch (err) {
      console.error("Error loading assignment form:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/assignments");
    }
  }
);

app.post(
  "/assignments",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const { patient_id, doctor_id, notes } = req.body;
    const userId = req.session.user.id;
    const userRole = req.session.user.role;

    try {
      // Check if patient already has an active assignment
      const [existingAssignments] = await pool.query(
        'SELECT * FROM assignments WHERE patient_id = ? AND status = "active"',
        [patient_id]
      );

      if (existingAssignments.length > 0) {
        req.flash("error_msg", "Patient already has an active assignment");
        return res.redirect("/assignments/new");
      }

      let assignedById = null;

      // Get the appropriate ID based on user role
      if (userRole === "employee") {
        const [employeeResults] = await pool.query(
          "SELECT id FROM employees WHERE user_id = ?",
          [userId]
        );

        if (employeeResults.length > 0) {
          assignedById = employeeResults[0].id;
        }
      } else if (userRole === "managing_director") {
        // For managing director, we'll use NULL for assigned_by since it's not in the employees table
        // Or create a temporary employee record for the managing director if needed
        const [employeeCheck] = await pool.query(
          "SELECT * FROM employees WHERE user_id = ?",
          [userId]
        );

        if (employeeCheck.length === 0) {
          // Get managing director details
          const [directorDetails] = await pool.query(
            "SELECT * FROM managing_directors WHERE user_id = ?",
            [userId]
          );

          if (directorDetails.length > 0) {
            const director = directorDetails[0];

            // Create employee record
            const [result] = await pool.query(
              "INSERT INTO employees (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
              [
                userId,
                director.first_name,
                director.last_name,
                director.email,
                director.phone,
              ]
            );

            assignedById = result.insertId;
          }
        } else {
          assignedById = employeeCheck[0].id;
        }
      }

      if (!assignedById) {
        req.flash(
          "error_msg",
          "Could not determine who is making the assignment"
        );
        return res.redirect("/assignments/new");
      }

      // Create assignment
      await pool.query(
        "INSERT INTO assignments (patient_id, doctor_id, assigned_by, notes, status) VALUES (?, ?, ?, ?, 'active')",
        [patient_id, doctor_id, assignedById, notes]
      );

      req.flash("success_msg", "Assignment created successfully");
      res.redirect("/assignments");
    } catch (err) {
      console.error("Error creating assignment:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/assignments/new");
    }
  }
);

app.put(
  "/assignments/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const assignmentId = req.params.id;
    const { status, notes } = req.body;

    try {
      await pool.query(
        "UPDATE assignments SET status = ?, notes = ? WHERE id = ?",
        [status, notes, assignmentId]
      );

      req.flash("success_msg", "Assignment updated successfully");
      res.redirect("/assignments");
    } catch (err) {
      console.error("Error updating assignment:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/assignments");
    }
  }
);

// Bills management
app.get(
  "/bills",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    try {
      const [bills] = await pool.query(`
      SELECT b.*, 
             CONCAT(p.first_name, ' ', p.last_name) as patient_name,
             CASE 
               WHEN b.generated_by_type = 'employee' THEN CONCAT(e.first_name, ' ', e.last_name)
               WHEN b.generated_by_type = 'doctor' THEN CONCAT(d.first_name, ' ', d.last_name)
               ELSE 'Unknown'
             END as generated_by_name
      FROM bills b
      JOIN patients p ON b.patient_id = p.id
      LEFT JOIN employees e ON b.generated_by = e.id AND b.generated_by_type = 'employee'
      LEFT JOIN doctors d ON b.generated_by = d.id AND b.generated_by_type = 'doctor'
      ORDER BY b.generated_date DESC
    `);

      res.render("bills", {
        title: "Bills Management",
        bills,
      });
    } catch (err) {
      console.error("Error fetching bills:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }
  }
);

app.get(
  "/bills/new",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    try {
      const [patients] = await pool.query(
        "SELECT id, first_name, last_name FROM patients"
      );

      res.render("bill-new", {
        title: "New Bill",
        patients,
      });
    } catch (err) {
      console.error("Error loading bill form:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/bills");
    }
  }
);

app.post(
  "/bills/new",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const { patient_id, amount, description, notes } = req.body;
    const userId = req.session.user.id;
    const userRole = req.session.user.role;

    try {
      let generatedById = null;

      // Get the appropriate ID based on user role
      if (userRole === "employee") {
        const [employeeResults] = await pool.query(
          "SELECT id FROM employees WHERE user_id = ?",
          [userId]
        );

        if (employeeResults.length > 0) {
          generatedById = employeeResults[0].id;
        }
      } else if (userRole === "managing_director") {
        // For managing director, create a temporary employee record if needed
        const [employeeCheck] = await pool.query(
          "SELECT * FROM employees WHERE user_id = ?",
          [userId]
        );

        if (employeeCheck.length === 0) {
          // Get managing director details
          const [directorDetails] = await pool.query(
            "SELECT * FROM managing_directors WHERE user_id = ?",
            [userId]
          );

          if (directorDetails.length > 0) {
            const director = directorDetails[0];

            // Create employee record
            const [result] = await pool.query(
              "INSERT INTO employees (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
              [
                userId,
                director.first_name,
                director.last_name,
                director.email,
                director.phone,
              ]
            );

            generatedById = result.insertId;
          }
        } else {
          generatedById = employeeCheck[0].id;
        }
      }

      if (!generatedById) {
        req.flash(
          "error_msg",
          "Could not determine who is generating the bill"
        );
        return res.redirect("/bills/new");
      }

      // Create bill
      await pool.query(
        "INSERT INTO bills (patient_id, amount, description, notes, generated_by, generated_by_type, status) VALUES (?, ?, ?, ?, ?, 'employee', 'pending')",
        [patient_id, amount, description, notes, generatedById]
      );

      req.flash("success_msg", "Bill created successfully");
      res.redirect("/bills");
    } catch (err) {
      console.error("Error creating bill:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/bills/new");
    }
  }
);

app.put(
  "/bills/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const billId = req.params.id;
    const { status } = req.body;

    try {
      const updateData = {
        status,
      };

      // If status is 'paid', set payment date
      if (status === "paid") {
        updateData.payment_date = new Date();
      }

      await pool.query("UPDATE bills SET ? WHERE id = ?", [updateData, billId]);

      req.flash("success_msg", "Bill updated successfully");
      res.redirect("/bills");
    } catch (err) {
      console.error("Error updating bill:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/bills");
    }
  }
);
// Bill receipt route
app.get(
  "/bills/:id/receipt",
  checkRole(["employee", "managing_director", "patient", "doctor"]),
  async (req, res) => {
    const billId = req.params.id;
    const userRole = req.session.user.role;
    const userId = req.session.user.id;

    try {
      // Get bill details
      const [billResults] = await pool.query(
        `
        SELECT b.*, 
               CONCAT(p.first_name, ' ', p.last_name) as patient_name,
               p.address as patient_address,
               p.phone as patient_phone,
               p.email as patient_email,
               p.id as patient_id,
               CASE 
                 WHEN b.generated_by_type = 'employee' THEN CONCAT(e.first_name, ' ', e.last_name)
                 WHEN b.generated_by_type = 'doctor' THEN CONCAT(d.first_name, ' ', d.last_name)
                 ELSE 'Unknown'
               END as generated_by_name
        FROM bills b
        JOIN patients p ON b.patient_id = p.id
        LEFT JOIN employees e ON b.generated_by = e.id AND b.generated_by_type = 'employee'
        LEFT JOIN doctors d ON b.generated_by = d.id AND b.generated_by_type = 'doctor'
        WHERE b.id = ?
      `,
        [billId]
      );

      if (billResults.length === 0) {
        req.flash("error_msg", "Bill not found");
        return res.redirect("/bills");
      }

      const bill = billResults[0];

      // Get full patient details
      const [patientResults] = await pool.query(
        `SELECT * FROM patients WHERE id = ?`,
        [bill.patient_id]
      );

      const patient =
        patientResults.length > 0
          ? patientResults[0]
          : {
              first_name: bill.patient_name.split(" ")[0],
              last_name: bill.patient_name.split(" ")[1] || "",
              email: bill.patient_email || "",
              phone: bill.patient_phone || "",
              address: bill.patient_address || "",
            };

      // If there's a consultation associated with this bill, get its details
      let consultation = null;
      if (bill.consultation_id) {
        const [consultationResults] = await pool.query(
          `
          SELECT c.*, CONCAT(d.first_name, ' ', d.last_name) as doctor_name
          FROM consultations c
          JOIN doctors d ON c.doctor_id = d.id
          WHERE c.id = ?
        `,
          [bill.consultation_id]
        );

        if (consultationResults.length > 0) {
          consultation = consultationResults[0];
        }
      }

      // If user is a patient, verify they own this bill
      if (userRole === "patient") {
        const [userPatientResults] = await pool.query(
          "SELECT p.id FROM patients p JOIN users u ON p.user_id = u.id WHERE u.id = ?",
          [userId]
        );

        if (
          userPatientResults.length === 0 ||
          userPatientResults[0].id !== bill.patient_id
        ) {
          req.flash("error_msg", "Unauthorized access");
          return res.redirect("/dashboard");
        }
      }
      // If user is a doctor, verify they are associated with this bill
      else if (userRole === "doctor") {
        // If bill has a consultation, check if doctor is associated with it
        if (bill.consultation_id) {
          const [doctorCheck] = await pool.query(
            "SELECT d.id FROM doctors d JOIN users u ON d.user_id = u.id WHERE u.id = ?",
            [userId]
          );

          if (doctorCheck.length === 0) {
            req.flash("error_msg", "Unauthorized access");
            return res.redirect("/dashboard");
          }

          const doctorId = doctorCheck[0].id;

          const [consultationCheck] = await pool.query(
            "SELECT * FROM consultations WHERE id = ? AND doctor_id = ?",
            [bill.consultation_id, doctorId]
          );

          if (consultationCheck.length === 0) {
            req.flash("error_msg", "Unauthorized access");
            return res.redirect("/dashboard");
          }
        } else {
          // If bill doesn't have a consultation, check if doctor generated it
          if (bill.generated_by_type !== "doctor") {
            req.flash("error_msg", "Unauthorized access");
            return res.redirect("/dashboard");
          }

          const [doctorCheck] = await pool.query(
            "SELECT d.id FROM doctors d JOIN users u ON d.user_id = u.id WHERE u.id = ?",
            [userId]
          );

          if (
            doctorCheck.length === 0 ||
            doctorCheck[0].id !== bill.generated_by
          ) {
            req.flash("error_msg", "Unauthorized access");
            return res.redirect("/dashboard");
          }
        }
      }

      // Render receipt
      res.render("bill-receipt", {
        title: "Bill Receipt",
        bill,
        patient, // Pass the patient object to the template
        consultation,
        currentDate: new Date(),
      });
    } catch (err) {
      console.error("Error generating receipt:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/bills");
    }
  }
);

// Lab Tests Routes
app.get(
  "/lab-tests",
  checkRole(["employee", "managing_director", "doctor"]),
  async (req, res) => {
    try {
      // Get all lab tests
      const [labTests] = await pool.query(
        "SELECT * FROM lab_tests ORDER BY name"
      );

      // Get patient lab tests with patient and test names
      const [patientTests] = await pool.query(`
      SELECT pt.*, p.first_name, p.last_name, 
             CONCAT(p.first_name, ' ', p.last_name) as patient_name,
             lt.name as test_name
      FROM patient_lab_tests pt
      JOIN patients p ON pt.patient_id = p.id
      JOIN lab_tests lt ON pt.lab_test_id = lt.id
      ORDER BY pt.requested_date DESC
    `);

      res.render("lab-tests", {
        title: "Lab Tests",
        labTests,
        patientTests,
        user: req.session.user,
      });
    } catch (err) {
      console.error("Error fetching lab tests:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/dashboard");
    }
  }
);

app.get(
  "/lab-tests/new-test",
  checkRole(["managing_director", "employee"]),
  (req, res) => {
    res.render("lab-test-new", { title: "Add New Lab Test" });
  }
);

app.post(
  "/lab-tests/new-test",
  checkRole(["managing_director", "employee"]),
  async (req, res) => {
    const { name, description, cost } = req.body;

    if (!name || !cost) {
      req.flash("error_msg", "Please provide test name and cost");
      return res.redirect("/lab-tests/new-test");
    }

    try {
      await pool.query(
        "INSERT INTO lab_tests (name, description, cost) VALUES (?, ?, ?)",
        [name, description, cost]
      );

      req.flash("success_msg", "Lab test created successfully");
      res.redirect("/lab-tests");
    } catch (err) {
      console.error("Error creating lab test:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/lab-tests/new-test");
    }
  }
);

app.get(
  "/lab-tests/request",
  checkRole(["employee", "managing_director", "doctor"]),
  async (req, res) => {
    try {
      // Get all patients
      const [patients] = await pool.query(
        "SELECT id, first_name, last_name FROM patients"
      );

      // Get all lab tests
      const [labTests] = await pool.query(
        "SELECT id, name, cost FROM lab_tests ORDER BY name"
      );

      // Check if a test_id was provided in the query
      const selectedTestId = req.query.test_id || "";

      res.render("lab-test-request", {
        title: "Request Lab Test",
        patients,
        labTests,
        selectedTestId,
      });
    } catch (err) {
      console.error("Error fetching data for lab test request:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/lab-tests");
    }
  }
);

app.post(
  "/lab-tests/request",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const { patient_id, lab_test_id, notes } = req.body;
    const userId = req.session.user.id;
    const userRole = req.session.user.role;

    if (!patient_id || !lab_test_id) {
      req.flash("error_msg", "Please select both patient and lab test");
      return res.redirect("/lab-tests/request");
    }

    try {
      let requestedById = null;
      let requesterType = "employee";

      // Get the appropriate ID based on user role
      if (userRole === "employee") {
        const [employeeResults] = await pool.query(
          "SELECT id FROM employees WHERE user_id = ?",
          [userId]
        );

        if (employeeResults.length > 0) {
          requestedById = employeeResults[0].id;
        }
      } else if (userRole === "managing_director") {
        // For managing director, create a temporary employee record if needed
        const [employeeCheck] = await pool.query(
          "SELECT * FROM employees WHERE user_id = ?",
          [userId]
        );

        if (employeeCheck.length === 0) {
          // Get managing director details
          const [directorDetails] = await pool.query(
            "SELECT * FROM managing_directors WHERE user_id = ?",
            [userId]
          );

          if (directorDetails.length > 0) {
            const director = directorDetails[0];

            // Create employee record
            const [result] = await pool.query(
              "INSERT INTO employees (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)",
              [
                userId,
                director.first_name,
                director.last_name,
                director.email,
                director.phone,
              ]
            );

            requestedById = result.insertId;
          }
        } else {
          requestedById = employeeCheck[0].id;
        }
      }

      // Create the lab test request
      await pool.query(
        "INSERT INTO patient_lab_tests (patient_id, lab_test_id, requested_by, requester_type, status, notes) VALUES (?, ?, ?, ?, 'pending', ?)",
        [patient_id, lab_test_id, requestedById, requesterType, notes || null]
      );

      req.flash("success_msg", "Lab test requested successfully");
      res.redirect("/lab-tests");
    } catch (err) {
      console.error("Error requesting lab test:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/lab-tests/request");
    }
  }
);

app.get(
  "/lab-tests/view/:id",
  checkRole(["employee", "managing_director", "doctor", "patient"]),
  async (req, res) => {
    const testId = req.params.id;

    try {
      // Get the patient test record
      const [patientTestResults] = await pool.query(
        "SELECT * FROM patient_lab_tests WHERE id = ?",
        [testId]
      );

      if (patientTestResults.length === 0) {
        req.flash("error_msg", "Lab test not found");
        return res.redirect("/lab-tests");
      }

      const patientTest = patientTestResults[0];

      // Get the lab test details
      const [labTestResults] = await pool.query(
        "SELECT * FROM lab_tests WHERE id = ?",
        [patientTest.lab_test_id]
      );

      if (labTestResults.length === 0) {
        req.flash("error_msg", "Lab test details not found");
        return res.redirect("/lab-tests");
      }

      const labTest = labTestResults[0];

      // Get the patient details
      const [patientResults] = await pool.query(
        "SELECT * FROM patients WHERE id = ?",
        [patientTest.patient_id]
      );

      if (patientResults.length === 0) {
        req.flash("error_msg", "Patient not found");
        return res.redirect("/lab-tests");
      }

      const patient = patientResults[0];

      // If user is a patient, verify they own this test
      if (req.session.user.role === "patient") {
        const [userPatientResults] = await pool.query(
          "SELECT p.id FROM patients p JOIN users u ON p.user_id = u.id WHERE u.id = ?",
          [req.session.user.id]
        );

        if (
          userPatientResults.length === 0 ||
          userPatientResults[0].id !== patientTest.patient_id
        ) {
          req.flash("error_msg", "Unauthorized access");
          return res.redirect("/dashboard");
        }
      }

      res.render("lab-test-view", {
        title: "Lab Test Details",
        patientTest,
        labTest,
        patient,
        user: req.session.user,
      });
    } catch (err) {
      console.error("Error viewing lab test:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/lab-tests");
    }
  }
);

app.get(
  "/lab-tests/update/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const testId = req.params.id;

    try {
      // Get the patient test record
      const [patientTestResults] = await pool.query(
        "SELECT * FROM patient_lab_tests WHERE id = ?",
        [testId]
      );

      if (patientTestResults.length === 0) {
        req.flash("error_msg", "Lab test not found");
        return res.redirect("/lab-tests");
      }

      const patientTest = patientTestResults[0];

      if (patientTest.status !== "pending") {
        req.flash("error_msg", "Only pending tests can be updated");
        return res.redirect("/lab-tests");
      }

      // Get the lab test details
      const [labTestResults] = await pool.query(
        "SELECT * FROM lab_tests WHERE id = ?",
        [patientTest.lab_test_id]
      );

      if (labTestResults.length === 0) {
        req.flash("error_msg", "Lab test details not found");
        return res.redirect("/lab-tests");
      }

      // Get the patient details
      const [patientResults] = await pool.query(
        "SELECT * FROM patients WHERE id = ?",
        [patientTest.patient_id]
      );

      if (patientResults.length === 0) {
        req.flash("error_msg", "Patient not found");
        return res.redirect("/lab-tests");
      }

      const patient = patientResults[0];

      res.render("lab-test-update", {
        title: "Update Lab Test Results",
        patientTest,
        labTest,
        patient,
      });
    } catch (err) {
      console.error("Error loading lab test update form:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/lab-tests");
    }
  }
);

app.post(
  "/lab-tests/update/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const testId = req.params.id;
    const { results } = req.body;

    if (!results) {
      req.flash("error_msg", "Please provide test results");
      return res.redirect(`/lab-tests/update/${testId}`);
    }

    try {
      // Update the test results
      await pool.query(
        "UPDATE patient_lab_tests SET results = ?, status = 'completed', completed_date = NOW() WHERE id = ?",
        [results, testId]
      );

      // Get the test details to check if it's associated with a consultation
      const [testDetails] = await pool.query(
        "SELECT * FROM patient_lab_tests WHERE id = ?",
        [testId]
      );

      if (testDetails.length > 0 && testDetails[0].consultation_id) {
        // Notify the doctor by redirecting to the consultation
        req.flash(
          "success_msg",
          "Lab test results updated successfully. The doctor has been notified."
        );
      } else {
        req.flash("success_msg", "Lab test results updated successfully");
      }

      res.redirect(`/lab-tests/view/${testId}`);
    } catch (err) {
      console.error("Error updating lab test results:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect(`/lab-tests/update/${testId}`);
    }
  }
);

app.put(
  "/lab-tests/cancel/:id",
  checkRole(["employee", "managing_director"]),
  async (req, res) => {
    const testId = req.params.id;

    try {
      // Cancel the test
      await pool.query(
        "UPDATE patient_lab_tests SET status = 'cancelled' WHERE id = ?",
        [testId]
      );

      req.flash("success_msg", "Lab test cancelled successfully");
      res.redirect("/lab-tests");
    } catch (err) {
      console.error("Error cancelling lab test:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/lab-tests");
    }
  }
);

// Doctor's Patients
app.get("/doctor/patients", checkRole(["doctor"]), async (req, res) => {
  const userId = req.session.user.id;
  const search = req.query.search || "";

  try {
    // Get doctor ID
    const [doctorResults] = await pool.query(
      `SELECT id FROM doctors WHERE user_id = ?`,
      [userId]
    );

    if (doctorResults.length === 0) {
      req.flash("error_msg", "Doctor record not found");
      return res.redirect("/dashboard");
    }

    const doctorId = doctorResults[0].id;

    // Get assigned patients
    let query = `
      SELECT p.*, a.assigned_date, a.status as assignment_status
      FROM patients p
      JOIN assignments a ON p.id = a.patient_id
      WHERE a.doctor_id = ? AND a.status = 'active'
    `;

    const queryParams = [doctorId];

    if (search) {
      query += ` AND (p.first_name LIKE ? OR p.last_name LIKE ? OR p.email LIKE ?)`;
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm);
    }

    query += ` ORDER BY p.first_name, p.last_name`;

    const [patients] = await pool.query(query, queryParams);

    res.render("doctor-patients", {
      title: "My Patients",
      patients,
    });
  } catch (err) {
    console.error("Error fetching patients:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/doctor/dashboard");
  }
});

// Doctor's Patient Details
app.get("/doctor/patients/:id", checkRole(["doctor"]), async (req, res) => {
  const patientId = req.params.id;
  const userId = req.session.user.id;

  try {
    // Get doctor ID
    const [doctorResults] = await pool.query(
      `SELECT id FROM doctors WHERE user_id = ?`,
      [userId]
    );

    if (doctorResults.length === 0) {
      req.flash("error_msg", "Doctor record not found");
      return res.redirect("/dashboard");
    }

    const doctorId = doctorResults[0].id;

    // Check if patient is assigned to this doctor
    const [assignmentCheck] = await pool.query(
      `SELECT * FROM assignments 
       WHERE doctor_id = ? AND patient_id = ? AND status = 'active'`,
      [doctorId, patientId]
    );

    if (assignmentCheck.length === 0) {
      req.flash("error_msg", "Patient not found or not assigned to you");
      return res.redirect("/doctor/patients");
    }

    // Get patient details
    const [patientResults] = await pool.query(
      `SELECT * FROM patients WHERE id = ?`,
      [patientId]
    );

    if (patientResults.length === 0) {
      req.flash("error_msg", "Patient not found");
      return res.redirect("/doctor/patients");
    }

    const patient = patientResults[0];

    // Get consultations
    const [consultations] = await pool.query(
      `SELECT * FROM consultations 
       WHERE doctor_id = ? AND patient_id = ? 
       ORDER BY consultation_date DESC`,
      [doctorId, patientId]
    );

    // Get lab tests
    const [labTests] = await pool.query(
      `SELECT pt.*, lt.name as test_name
       FROM patient_lab_tests pt
       JOIN lab_tests lt ON pt.lab_test_id = lt.id
       WHERE pt.patient_id = ?
       ORDER BY pt.requested_date DESC`,
      [patientId]
    );

    // Get bills
    const [bills] = await pool.query(
      `SELECT * FROM bills 
       WHERE patient_id = ? 
       ORDER BY generated_date DESC`,
      [patientId]
    );

    res.render("doctor-patient-details", {
      title: "Patient Details",
      patient,
      consultations,
      labTests,
      bills,
    });
  } catch (err) {
    console.error("Error fetching patient details:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/doctor/patients");
  }
});

// Doctor's Consultations
app.get("/doctor/consultations", checkRole(["doctor"]), async (req, res) => {
  const userId = req.session.user.id;
  const status = req.query.status || "";

  try {
    // Get doctor ID
    const [doctorResults] = await pool.query(
      `SELECT id FROM doctors WHERE user_id = ?`,
      [userId]
    );

    if (doctorResults.length === 0) {
      req.flash("error_msg", "Doctor record not found");
      return res.redirect("/dashboard");
    }

    const doctorId = doctorResults[0].id;

    // Get consultations
    let query = `
      SELECT c.*, CONCAT(p.first_name, ' ', p.last_name) as patient_name
      FROM consultations c
      JOIN patients p ON c.patient_id = p.id
      WHERE c.doctor_id = ?
    `;

    const queryParams = [doctorId];

    if (status) {
      query += ` AND c.status = ?`;
      queryParams.push(status);
    }

    query += ` ORDER BY c.consultation_date DESC`;

    const [consultations] = await pool.query(query, queryParams);

    res.render("doctor-consultations", {
      title: "Consultations",
      consultations,
      activeStatus: status,
    });
  } catch (err) {
    console.error("Error fetching consultations:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/doctor/dashboard");
  }
});

// Doctor's New Consultation
app.get(
  "/doctor/consultations/new",
  checkRole(["doctor"]),
  async (req, res) => {
    const userId = req.session.user.id;
    const patientId = req.query.patient_id || "";

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Get assigned patients
      const [patients] = await pool.query(
        `SELECT p.* 
       FROM patients p
       JOIN assignments a ON p.id = a.patient_id
       WHERE a.doctor_id = ? AND a.status = 'active'
       ORDER BY p.first_name, p.last_name`,
        [doctorId]
      );

      let selectedPatient = null;
      if (patientId) {
        // Check if patient is assigned to this doctor
        const [patientCheck] = await pool.query(
          `SELECT p.* 
         FROM patients p
         JOIN assignments a ON p.id = a.patient_id
         WHERE a.doctor_id = ? AND p.id = ? AND a.status = 'active'`,
          [doctorId, patientId]
        );

        if (patientCheck.length > 0) {
          selectedPatient = patientCheck[0];
        }
      }

      res.render("doctor-consultation-new", {
        title: "New Consultation",
        patients,
        selectedPatient,
      });
    } catch (err) {
      console.error("Error loading consultation form:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctor/consultations");
    }
  }
);

// Doctor's Create Consultation
app.post(
  "/doctor/consultations/new",
  checkRole(["doctor"]),
  async (req, res) => {
    const userId = req.session.user.id;
    const {
      patient_id,
      symptoms,
      diagnosis,
      treatment,
      notes,
      complete_consultation,
    } = req.body;

    if (!patient_id || !symptoms) {
      req.flash("error_msg", "Patient and symptoms are required");
      return res.redirect("/doctor/consultations/new");
    }

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Check if patient is assigned to this doctor
      const [assignmentCheck] = await pool.query(
        `SELECT * FROM assignments 
       WHERE doctor_id = ? AND patient_id = ? AND status = 'active'`,
        [doctorId, patient_id]
      );

      if (assignmentCheck.length === 0) {
        req.flash("error_msg", "Patient not assigned to you");
        return res.redirect("/doctor/consultations/new");
      }

      // Create consultation
      const status = complete_consultation ? "completed" : "ongoing";

      const [result] = await pool.query(
        `INSERT INTO consultations 
       (patient_id, doctor_id, symptoms, diagnosis, treatment, notes, status) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [patient_id, doctorId, symptoms, diagnosis, treatment, notes, status]
      );

      req.flash("success_msg", "Consultation created successfully");
      res.redirect(`/doctor/consultations/${result.insertId}`);
    } catch (err) {
      console.error("Error creating consultation:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctor/consultations/new");
    }
  }
);

// View Consultation
app.get(
  "/doctor/consultations/:id",
  checkRole(["doctor"]),
  async (req, res) => {
    const consultationId = req.params.id;
    const userId = req.session.user.id;

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Get consultation
      const [consultationResults] = await pool.query(
        `SELECT * FROM consultations 
       WHERE id = ? AND doctor_id = ?`,
        [consultationId, doctorId]
      );

      if (consultationResults.length === 0) {
        req.flash("error_msg", "Consultation not found");
        return res.redirect("/doctor/consultations");
      }

      const consultation = consultationResults[0];

      // Get patient
      const [patientResults] = await pool.query(
        `SELECT * FROM patients WHERE id = ?`,
        [consultation.patient_id]
      );

      if (patientResults.length === 0) {
        req.flash("error_msg", "Patient not found");
        return res.redirect("/doctor/consultations");
      }

      const patient = patientResults[0];

      // Get related lab tests
      const [labTests] = await pool.query(
        `SELECT pt.*, lt.name as test_name
       FROM patient_lab_tests pt
       JOIN lab_tests lt ON pt.lab_test_id = lt.id
       WHERE pt.patient_id = ? AND pt.consultation_id = ?
       ORDER BY pt.requested_date DESC`,
        [patient.id, consultationId]
      );

      // Get related bills
      const [bills] = await pool.query(
        `SELECT * FROM bills 
       WHERE patient_id = ? AND consultation_id = ?
       ORDER BY generated_date DESC`,
        [patient.id, consultationId]
      );

      res.render("doctor-consultation-view", {
        title: "Consultation Details",
        consultation,
        patient,
        labTests,
        bills,
      });
    } catch (err) {
      console.error("Error fetching consultation:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctor/consultations");
    }
  }
);

// Edit Consultation Form
app.get(
  "/doctor/consultations/edit/:id",
  checkRole(["doctor"]),
  async (req, res) => {
    const consultationId = req.params.id;
    const userId = req.session.user.id;

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Get consultation
      const [consultationResults] = await pool.query(
        `SELECT * FROM consultations 
       WHERE id = ? AND doctor_id = ?`,
        [consultationId, doctorId]
      );

      if (consultationResults.length === 0) {
        req.flash("error_msg", "Consultation not found");
        return res.redirect("/doctor/consultations");
      }

      const consultation = consultationResults[0];

      if (consultation.status !== "ongoing") {
        req.flash("error_msg", "Only ongoing consultations can be edited");
        return res.redirect(`/doctor/consultations/${consultationId}`);
      }

      // Get patient
      const [patientResults] = await pool.query(
        `SELECT * FROM patients WHERE id = ?`,
        [consultation.patient_id]
      );

      if (patientResults.length === 0) {
        req.flash("error_msg", "Patient not found");
        return res.redirect("/doctor/consultations");
      }

      const patient = patientResults[0];

      res.render("doctor-consultation-edit", {
        title: "Edit Consultation",
        consultation,
        patient,
      });
    } catch (err) {
      console.error("Error loading edit consultation form:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctor/consultations");
    }
  }
);

// Update Consultation
app.post(
  "/doctor/consultations/edit/:id",
  checkRole(["doctor"]),
  async (req, res) => {
    const consultationId = req.params.id;
    const userId = req.session.user.id;
    const { symptoms, diagnosis, treatment, notes, complete_consultation } =
      req.body;

    if (!symptoms) {
      req.flash("error_msg", "Symptoms are required");
      return res.redirect(`/doctor/consultations/edit/${consultationId}`);
    }

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Check if consultation exists and belongs to this doctor
      const [consultationCheck] = await pool.query(
        `SELECT * FROM consultations 
       WHERE id = ? AND doctor_id = ?`,
        [consultationId, doctorId]
      );

      if (consultationCheck.length === 0) {
        req.flash("error_msg", "Consultation not found");
        return res.redirect("/doctor/consultations");
      }

      if (consultationCheck[0].status !== "ongoing") {
        req.flash("error_msg", "Only ongoing consultations can be edited");
        return res.redirect(`/doctor/consultations/${consultationId}`);
      }

      // Update consultation
      const status = complete_consultation ? "completed" : "ongoing";

      await pool.query(
        `UPDATE consultations 
       SET symptoms = ?, diagnosis = ?, treatment = ?, notes = ?, status = ?
       WHERE id = ?`,
        [symptoms, diagnosis, treatment, notes, status, consultationId]
      );

      req.flash("success_msg", "Consultation updated successfully");
      res.redirect(`/doctor/consultations/${consultationId}`);
    } catch (err) {
      console.error("Error updating consultation:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect(`/doctor/consultations/edit/${consultationId}`);
    }
  }
);

// Complete Consultation
app.post(
  "/doctor/consultations/:id/complete",
  checkRole(["doctor"]),
  async (req, res) => {
    const consultationId = req.params.id;
    const userId = req.session.user.id;

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Check if consultation exists and belongs to this doctor
      const [consultationCheck] = await pool.query(
        `SELECT * FROM consultations 
       WHERE id = ? AND doctor_id = ?`,
        [consultationId, doctorId]
      );

      if (consultationCheck.length === 0) {
        req.flash("error_msg", "Consultation not found");
        return res.redirect("/doctor/consultations");
      }

      if (consultationCheck[0].status !== "ongoing") {
        req.flash("error_msg", "Only ongoing consultations can be completed");
        return res.redirect(`/doctor/consultations/${consultationId}`);
      }

      // Update consultation status
      await pool.query(
        `UPDATE consultations SET status = 'completed' WHERE id = ?`,
        [consultationId]
      );

      req.flash("success_msg", "Consultation marked as completed");
      res.redirect(`/doctor/consultations/${consultationId}`);
    } catch (err) {
      console.error("Error completing consultation:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect(`/doctor/consultations/${consultationId}`);
    }
  }
);

// Cancel Consultation
app.post(
  "/doctor/consultations/:id/cancel",
  checkRole(["doctor"]),
  async (req, res) => {
    const consultationId = req.params.id;
    const userId = req.session.user.id;

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Check if consultation exists and belongs to this doctor
      const [consultationCheck] = await pool.query(
        `SELECT * FROM consultations 
       WHERE id = ? AND doctor_id = ?`,
        [consultationId, doctorId]
      );

      if (consultationCheck.length === 0) {
        req.flash("error_msg", "Consultation not found");
        return res.redirect("/doctor/consultations");
      }

      if (consultationCheck[0].status !== "ongoing") {
        req.flash("error_msg", "Only ongoing consultations can be cancelled");
        return res.redirect(`/doctor/consultations/${consultationId}`);
      }

      // Update consultation status
      await pool.query(
        `UPDATE consultations SET status = 'cancelled' WHERE id = ?`,
        [consultationId]
      );

      req.flash("success_msg", "Consultation cancelled");
      res.redirect(`/doctor/consultations/${consultationId}`);
    } catch (err) {
      console.error("Error cancelling consultation:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect(`/doctor/consultations/${consultationId}`);
    }
  }
);

// Doctor's Lab Test Request
app.get(
  "/doctor/lab-tests/request",
  checkRole(["doctor"]),
  async (req, res) => {
    const userId = req.session.user.id;
    const patientId = req.query.patient_id || "";
    const consultationId = req.query.consultation_id || "";

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Get assigned patients
      const [patients] = await pool.query(
        `SELECT p.* 
       FROM patients p
       JOIN assignments a ON p.id = a.patient_id
       WHERE a.doctor_id = ? AND a.status = 'active'
       ORDER BY p.first_name, p.last_name`,
        [doctorId]
      );

      // Get all lab tests - Make sure this query is working
      console.log("Fetching lab tests...");
      const [labTests] = await pool.query(
        "SELECT id, name, cost FROM lab_tests ORDER BY name"
      );

      console.log("Lab Tests from DB:", labTests); // Debug log to check what's being returned

      // Check if lab_tests table has data
      if (!labTests || labTests.length === 0) {
        console.log("WARNING: No lab tests found in the database!");

        // If no lab tests exist, let's create a sample one for testing
        try {
          console.log("Attempting to create a sample lab test...");
          await pool.query(
            "INSERT INTO lab_tests (name, description, cost) VALUES (?, ?, ?)",
            [
              "Complete Blood Count",
              "Basic blood test that checks various components of blood",
              1500,
            ]
          );
          console.log("Sample lab test created successfully");

          // Fetch again after creating
          const [newLabTests] = await pool.query(
            "SELECT id, name, cost FROM lab_tests ORDER BY name"
          );
          console.log("Lab Tests after creation:", newLabTests);

          // Use the newly created tests
          labTests = newLabTests;
        } catch (createErr) {
          console.error("Error creating sample lab test:", createErr);
        }
      }

      let selectedPatient = null;
      let selectedConsultation = null;
      let consultations = [];

      if (patientId) {
        // Check if patient is assigned to this doctor
        const [patientCheck] = await pool.query(
          `SELECT p.* 
         FROM patients p
         JOIN assignments a ON p.id = a.patient_id
         WHERE a.doctor_id = ? AND p.id = ? AND a.status = 'active'`,
          [doctorId, patientId]
        );

        if (patientCheck.length > 0) {
          selectedPatient = patientCheck[0];

          // Get patient's consultations
          [consultations] = await pool.query(
            `SELECT * FROM consultations 
           WHERE doctor_id = ? AND patient_id = ? 
           ORDER BY consultation_date DESC`,
            [doctorId, patientId]
          );

          if (consultationId) {
            // Check if consultation exists
            const [consultationCheck] = await pool.query(
              `SELECT * FROM consultations 
             WHERE id = ? AND doctor_id = ? AND patient_id = ?`,
              [consultationId, doctorId, patientId]
            );

            if (consultationCheck.length > 0) {
              selectedConsultation = consultationCheck[0];
            }
          }
        }
      }

      // Check if the lab_tests table exists
      try {
        const [tables] = await pool.query("SHOW TABLES LIKE 'lab_tests'");
        console.log("Lab tests table check:", tables);

        if (tables.length === 0) {
          console.log("WARNING: lab_tests table does not exist!");

          // Create the table if it doesn't exist
          try {
            await pool.query(`
              CREATE TABLE IF NOT EXISTS lab_tests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                cost DECIMAL(10,2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
              )
            `);
            console.log("Created lab_tests table");

            // Insert some sample data
            await pool.query(`
              INSERT INTO lab_tests (name, description, cost) VALUES
              ('Complete Blood Count', 'Basic blood test that checks various components of blood', 1500),
              ('Blood Glucose Test', 'Measures the amount of glucose in blood', 800),
              ('Lipid Profile', 'Measures cholesterol and triglycerides', 2000),
              ('Liver Function Test', 'Assesses liver function', 2500),
              ('Kidney Function Test', 'Assesses kidney function', 2500)
            `);
            console.log("Added sample lab tests");

            // Fetch the newly created tests
            const [newTests] = await pool.query(
              "SELECT id, name, cost FROM lab_tests ORDER BY name"
            );
            console.log("New lab tests:", newTests);

            // Use the newly created tests
            labTests = newTests;
          } catch (createErr) {
            console.error("Error creating lab_tests table:", createErr);
          }
        }
      } catch (tableErr) {
        console.error("Error checking for lab_tests table:", tableErr);
      }

      console.log("Rendering template with lab tests:", labTests);

      res.render("doctor-lab-test-request", {
        title: "Request Lab Test",
        patients,
        labTests, // Make sure this is being passed correctly
        selectedPatient,
        selectedConsultation,
        consultations,
        selectedTestId: req.query.test_id || "",
      });
    } catch (err) {
      console.error("Error loading lab test request form:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctor/dashboard");
    }
  }
);

// Doctor's Submit Lab Test Request
app.post(
  "/doctor/lab-tests/request",
  checkRole(["doctor"]),
  async (req, res) => {
    const userId = req.session.user.id;
    const { patient_id, lab_test_id, consultation_id, notes } = req.body;

    if (!patient_id || !lab_test_id) {
      req.flash("error_msg", "Please select both patient and lab test");
      return res.redirect("/doctor/lab-tests/request");
    }

    try {
      // Get doctor ID
      const [doctorResults] = await pool.query(
        `SELECT id FROM doctors WHERE user_id = ?`,
        [userId]
      );

      if (doctorResults.length === 0) {
        req.flash("error_msg", "Doctor record not found");
        return res.redirect("/dashboard");
      }

      const doctorId = doctorResults[0].id;

      // Check if patient is assigned to this doctor
      const [assignmentCheck] = await pool.query(
        `SELECT * FROM assignments 
       WHERE doctor_id = ? AND patient_id = ? AND status = 'active'`,
        [doctorId, patient_id]
      );

      if (assignmentCheck.length === 0) {
        req.flash("error_msg", "Patient not assigned to you");
        return res.redirect("/doctor/lab-tests/request");
      }

      // If consultation_id is provided, check if it exists and belongs to this doctor
      if (consultation_id) {
        const [consultationCheck] = await pool.query(
          `SELECT * FROM consultations 
         WHERE id = ? AND doctor_id = ? AND patient_id = ?`,
          [consultation_id, doctorId, patient_id]
        );

        if (consultationCheck.length === 0) {
          req.flash("error_msg", "Consultation not found");
          return res.redirect("/doctor/lab-tests/request");
        }
      }

      // Create the lab test request
      await pool.query(
        `INSERT INTO patient_lab_tests 
       (patient_id, lab_test_id, consultation_id, requested_by, requester_type, status, notes) 
       VALUES (?, ?, ?, ?, 'doctor', 'pending', ?)`,
        [
          patient_id,
          lab_test_id,
          consultation_id || null,
          doctorId,
          notes || null,
        ]
      );

      req.flash("success_msg", "Lab test requested successfully");

      if (consultation_id) {
        res.redirect(`/doctor/consultations/${consultation_id}`);
      } else {
        res.redirect("/doctor/lab-tests");
      }
    } catch (err) {
      console.error("Error requesting lab test:", err);
      req.flash("error_msg", "An error occurred. Please try again.");
      return res.redirect("/doctor/lab-tests/request");
    }
  }
);

// Doctor's Generate Bill
app.get("/doctor/bills/new", checkRole(["doctor"]), async (req, res) => {
  const userId = req.session.user.id;
  const patientId = req.query.patient_id || "";
  const consultationId = req.query.consultation_id || "";

  try {
    // Get doctor ID
    const [doctorResults] = await pool.query(
      `SELECT id FROM doctors WHERE user_id = ?`,
      [userId]
    );

    if (doctorResults.length === 0) {
      req.flash("error_msg", "Doctor record not found");
      return res.redirect("/dashboard");
    }

    const doctorId = doctorResults[0].id;

    // Get assigned patients
    const [patients] = await pool.query(
      `SELECT p.* 
       FROM patients p
       JOIN assignments a ON p.id = a.patient_id
       WHERE a.doctor_id = ? AND a.status = 'active'
       ORDER BY p.first_name, p.last_name`,
      [doctorId]
    );

    let selectedPatient = null;
    let selectedConsultation = null;
    let consultations = [];

    if (patientId) {
      // Check if patient is assigned to this doctor
      const [patientCheck] = await pool.query(
        `SELECT p.* 
         FROM patients p
         JOIN assignments a ON p.id = a.patient_id
         WHERE a.doctor_id = ? AND p.id = ? AND a.status = 'active'`,
        [doctorId, patientId]
      );

      if (patientCheck.length > 0) {
        selectedPatient = patientCheck[0];

        // Get patient's consultations
        [consultations] = await pool.query(
          `SELECT * FROM consultations 
           WHERE doctor_id = ? AND patient_id = ? 
           ORDER BY consultation_date DESC`,
          [doctorId, patientId]
        );

        if (consultationId) {
          // Check if consultation exists
          const [consultationCheck] = await pool.query(
            `SELECT * FROM consultations 
             WHERE id = ? AND doctor_id = ? AND patient_id = ?`,
            [consultationId, doctorId, patientId]
          );

          if (consultationCheck.length > 0) {
            selectedConsultation = consultationCheck[0];
          }
        }
      }
    }

    res.render("doctor-bill-new", {
      title: "Generate Bill",
      patients,
      consultations,
      selectedPatient,
      selectedConsultation,
    });
  } catch (err) {
    console.error("Error loading bill form:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/doctor/dashboard");
  }
});

// Doctor's Create Bill
app.post("/doctor/bills/new", checkRole(["doctor"]), async (req, res) => {
  const userId = req.session.user.id;
  const { patient_id, consultation_id, amount, description, notes } = req.body;

  if (!patient_id || !amount) {
    req.flash("error_msg", "Patient and amount are required");
    return res.redirect("/doctor/bills/new");
  }

  try {
    // Get doctor ID
    const [doctorResults] = await pool.query(
      `SELECT id FROM doctors WHERE user_id = ?`,
      [userId]
    );

    if (doctorResults.length === 0) {
      req.flash("error_msg", "Doctor record not found");
      return res.redirect("/dashboard");
    }

    const doctorId = doctorResults[0].id;

    // Check if patient is assigned to this doctor
    const [assignmentCheck] = await pool.query(
      `SELECT * FROM assignments 
       WHERE doctor_id = ? AND patient_id = ? AND status = 'active'`,
      [doctorId, patient_id]
    );

    if (assignmentCheck.length === 0) {
      req.flash("error_msg", "Patient not assigned to you");
      return res.redirect("/doctor/bills/new");
    }

    // If consultation_id is provided, check if it exists and belongs to this doctor
    if (consultation_id) {
      const [consultationCheck] = await pool.query(
        `SELECT * FROM consultations 
         WHERE id = ? AND doctor_id = ? AND patient_id = ?`,
        [consultation_id, doctorId, patient_id]
      );

      if (consultationCheck.length === 0) {
        req.flash("error_msg", "Consultation not found");
        return res.redirect("/doctor/bills/new");
      }
    }

    // Create bill
    await pool.query(
      `INSERT INTO bills 
       (patient_id, consultation_id, amount, description, notes, generated_by, generated_by_type, status) 
       VALUES (?, ?, ?, ?, ?, ?, 'doctor', 'pending')`,
      [
        patient_id,
        consultation_id || null,
        amount,
        description,
        notes,
        doctorId,
      ]
    );

    req.flash("success_msg", "Bill generated successfully");

    if (consultation_id) {
      res.redirect(`/doctor/consultations/${consultation_id}`);
    } else {
      res.redirect(`/doctor/patients/${patient_id}`);
    }
  } catch (err) {
    console.error("Error generating bill:", err);
    req.flash("error_msg", "An error occurred. Please try again.");
    return res.redirect("/doctor/bills/new");
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
