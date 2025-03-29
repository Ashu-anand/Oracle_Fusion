This program can be used to assign the user role in bulk. For the following setups and files are required
1) config/config.yaml: This file needs to be created in the config folder under the Oracle_Fusion folder. The content of the file will be as follows
    oracle_fusion:  
      instance_code: "xx-aaaa"
      instance_name: "prd01"
      username: "johndoe"
      password: "password@123"
  
2) The second file will be User_Data_Access.csv, which will also reside inside the same Oracle_Fusion Folder, and it will contain 4 columns as follows
   UserName, RoleNameCr, SecurityContext, SecurityContextValue
   johndoe, Accounts Receivable Manager, Business unit, USA BU
   johndoe, Accounts Receivable Manager, Business unit, UK BU
   johndoe, Inventory Manager, Inventory organization, VAN
   johndoe, Inventory Manager, Inventory organization, CAN
   johndoe, Inventory Manager, Inventory organization, DAN
