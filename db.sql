-- Database Schema for Baraka General Medical Clinic

CREATE DATABASE IF NOT EXISTS baraka_clinic;
USE baraka_clinic;

-- Users table for authentication
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('patient', 'doctor', 'employee', 'managing-director') NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Patients table
CREATE TABLE patients (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  first_name VARCHAR(50) NOT NULL,
  last_name VARCHAR(50) NOT NULL,
  email VARCHAR(100) UNIQUE,
  phone VARCHAR(20),
  address TEXT,
  date_of_birth DATE,
  gender ENUM('male', 'female', 'other'),
  blood_group VARCHAR(5),
  medical_history TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Doctors table
CREATE TABLE doctors (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  first_name VARCHAR(50) NOT NULL,
  last_name VARCHAR(50) NOT NULL,
  email VARCHAR(100) UNIQUE,
  phone VARCHAR(20),
  specialization VARCHAR(100),
  qualification TEXT,
  experience INT,
  salary DECIMAL(10, 2),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);





-- Assignments table (linking patients to doctors)
CREATE TABLE assignments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT,
  doctor_id INT,
  assigned_by INT, -- admin id
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status ENUM('active', 'completed', 'cancelled') DEFAULT 'active',
  notes TEXT,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
  FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE,
  FOREIGN KEY (assigned_by) REFERENCES admins(id) ON DELETE SET NULL
);

-- Bills table
CREATE TABLE bills (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT,
  amount DECIMAL(10, 2) NOT NULL,
  description TEXT,
  status ENUM('pending', 'paid', 'cancelled') DEFAULT 'pending',
  generated_by INT, -- admin id
  generated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  payment_date TIMESTAMP NULL,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
  FOREIGN KEY (generated_by) REFERENCES admins(id) ON DELETE SET NULL
);

-- First, drop the existing foreign key constraint
ALTER TABLE assignments
DROP FOREIGN KEY assignments_ibfk_3;

-- Then add a new column to track who created the assignment (admin or superadmin)
ALTER TABLE assignments
ADD COLUMN creator_type ENUM('admin', 'superadmin') NOT NULL DEFAULT 'admin' AFTER assigned_by;

-- Update the app.js file to handle this new schema





-- Update the role enum in the users table
ALTER TABLE users 
MODIFY COLUMN role ENUM('patient', 'doctor', 'employee', 'managing_director') NOT NULL;

-- Rename the superadmins table to managing_directors
RENAME TABLE superadmins TO managing_directors;

-- Rename the admins table to employees
RENAME TABLE admins TO employees;

-- Update existing user roles in the database
UPDATE users SET role = 'managing_director' WHERE role = 'superadmin';
UPDATE users SET role = 'employee' WHERE role = 'admin';

-- Create lab tests table
CREATE TABLE lab_tests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  cost DECIMAL(10, 2) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create patient lab tests table
CREATE TABLE patient_lab_tests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  lab_test_id INT NOT NULL,
  requested_by INT, -- employee id
  requested_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
  results TEXT,
  completed_date TIMESTAMP NULL,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
  FOREIGN KEY (lab_test_id) REFERENCES lab_tests(id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by) REFERENCES employees(id) ON DELETE SET NULL
);


-- Create consultations table
CREATE TABLE consultations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  patient_id INT NOT NULL,
  doctor_id INT NOT NULL,
  symptoms TEXT NOT NULL,
  diagnosis TEXT,
  treatment TEXT,
  notes TEXT,
  status ENUM('ongoing', 'completed', 'cancelled') DEFAULT 'ongoing',
  consultation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
  FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
);

-- Update bills table to add consultation_id and generated_by_type fields
ALTER TABLE bills 
ADD COLUMN consultation_id INT NULL,
ADD COLUMN generated_by_type ENUM('employee', 'doctor') DEFAULT 'employee',
ADD COLUMN notes TEXT,
ADD FOREIGN KEY (consultation_id) REFERENCES consultations(id) ON DELETE SET NULL;

-- Update patient_lab_tests table to add consultation_id and requester_type fields
ALTER TABLE patient_lab_tests 
ADD COLUMN consultation_id INT NULL,
ADD COLUMN requester_type ENUM('employee', 'doctor') DEFAULT 'employee',
ADD COLUMN notes TEXT,
ADD FOREIGN KEY (consultation_id) REFERENCES consultations(id) ON DELETE SET NULL;