# **Bulk User Role Assignment for Oracle Fusion**

## 📌 Overview
This program allows **bulk user role assignments** in **Oracle Fusion Cloud**.

## 📂 Required Setup and Files

### **1️⃣ Configuration File (`config/config.yaml`)**
Create a `config.yaml` file in the **`config/`** folder under the `Oracle_Fusion/` directory.

#### **Example:**
```yaml
oracle_fusion:
  instance_code: "xx-aaaa"
  instance_name: "prd01"
  username: "johndoe"
  password: "password@123"
```

### 2️⃣ User Data File (User_Data_Access.csv)
This file should be placed inside the Oracle_Fusion/ folder.

#### Expected Format (CSV columns):
UserName | RoleNameCr | SecurityContext | SecurityContextValue
--- | --- | --- | ---
johndoe | Accounts Receivable Manager | Business unit | USA BU
johndoe | Accounts Receivable Manager | Business unit | UK BU
johndoe | Inventory Manager | Inventory organization | VAN
johndoe | Inventory Manager | Inventory organization | CAN
johndoe | Inventory Manager | Inventory organization | DAN

### 🚀 How to Use
Ensure both config/config.yaml and User_Data_Access.csv exist in the Oracle_Fusion directory.

### Run the script:
python assign_role.py

#### The script will process the CSV and assign roles accordingly.

### 📌 Notes
Ensure correct Oracle Fusion API credentials are provided in config.yaml.

The script uses Oracle Fusion REST APIs to assign roles.

Log files are generated for tracking errors and assignments.

🤝 Contributing
Feel free to submit issues or pull requests for improvements.

📜 License
This project is licensed under the MIT License.
