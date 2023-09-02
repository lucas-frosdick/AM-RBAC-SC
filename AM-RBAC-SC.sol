// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/*Access Monitoring with RBAC smart contract*/
contract AM_SC_RBAC is AccessControl
{

    mapping (bytes32 => Role_Struct) RBAC_Roles; //stores the user roles required for RBAC implementation
    mapping (address => User_Struct) Users_Info; //stores the user profiles required for RBAC implementation
    mapping (bytes32 => System_Struct) Systems;  //stores the systems availabe to users and the roles required to access them
    mapping (address => User_RBAC_Session) User_Sessions; //stores the RBAC sessions created by the user

    bytes32[] Roles; //array of role hashes
    address[] Users; //array of user addresses
    bytes32[] Systems_Arr; //array of system hashes
    string[] Abuse_Log; //array storing any abuses reported by the smart contact

    bytes32 SOC_Role = keccak256("SOC_DEFAULT_ROLE"); //default role for the Security Operations Team

    uint public Index_Role; //number of current roles
    uint public Index_User; //number of current users
    uint public Index_System; //number of current systems
    uint public Index_Session; //number of current sessions

    //default monitoring struct given to each user upon initialisation
    User_Monitoring_Struct Init_Monitoring = User_Monitoring_Struct(
        {
            Prev_Request_Fail: false,
            Request_Deny_Count: 0,
            Last_Request_Time: 0,
            User_Restricted: false,
            User_Suspended_Count: 0,
            Resource_Request_Fail: false,
            Last_Requested_Resource: "NONE"
        }
    );

    //format of the permissions for resources on a system
    struct Permissions
    {
        bool Read;
        bool Write;
        bool Execute;
    }

    //format for the resources a role can access on a system
    struct Allowed_Resources_struct
    {
        string Resource_Name;
        Permissions Resource_Permissions;
        uint Resource_Timestamp;
    }
    
    //format of the role information
    struct Role_Struct
    {

        string Role_Name;
        string Role_Information;
        mapping(bytes32 => Allowed_Resources_struct) Allowed_Resources;
        bytes32[] Allowed_Resources_Hash;
        uint Allowed_Resources_Count;
        uint Role_Timestamp;
        uint Role_Index;
    }

    //format of the user monitoring information
    struct User_Monitoring_Struct
    {
        bool Prev_Request_Fail;
        uint Request_Deny_Count;
        uint Last_Request_Time;
        bool User_Restricted;
        uint User_Suspended_Count;
        bool Resource_Request_Fail;
        string Last_Requested_Resource;
    }

    //format of the user information
    struct User_Struct
    {
        bytes32[] User_Role_Hash;
        uint User_Role_Count;
        User_Monitoring_Struct Monitor_Behavior;
        string User_Information;
        uint User_Joined;
        uint User_Index;
    }

    //format for the resources on a system
    struct System_Resources
    {
        string Resource_Name;
        uint Resource_Timestamp;
    }

    //format of the system information
    struct System_Struct
    {
        bytes32[] Required_Role_Hash;
        uint System_Role_Count;
        mapping (bytes32 => System_Resources) System_Resources;
        uint System_Resource_Count;
        string System_Name;
        string System_Information;
        uint System_Added;
        uint System_Index;
    }

    //format of the RBAC session
    struct User_RBAC_Session
    {
        bytes32[] Session_Role_Hash;
        uint Session_Init_Time;
        bytes32 System_Hash;
        uint Session_Index;
    }

    //upon init of the smart contract
    constructor()
    {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender); //create admin as user who deployed the smart contract
        Index_Role = 0; // set number of roles to 0
        Index_User = 0; // set number of users to 0
        Index_System = 0;   // set number of systems to 0
        Index_Session = 0; //set number of sessions to 0
    }

    /*Add a role to the smart contract, takes the name of the role and information about the role*/
    function Add_Role(string memory Role, string memory Info, string[] memory Resources, int[] memory Resource_Permissions) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));   //ensure the only user who can execute the function is an admin
        bytes32 Role_Hash = keccak256(abi.encodePacked(Role));  //generate keccak256 hash of role
        require(RBAC_Roles[Role_Hash].Role_Timestamp == 0, "Role Exists");  //ensure that the role does not already exist

        //initalise the role structure and store it within RBAC_Roles
        RBAC_Roles[Role_Hash].Role_Name = Role;
        RBAC_Roles[Role_Hash].Role_Information = Info;
        RBAC_Roles[Role_Hash].Role_Timestamp = block.timestamp;
        RBAC_Roles[Role_Hash].Role_Index = Index_Role;

        //Adding the required resources to the role
        for (uint256 i = 0; i < Resources.length; i++) 
        {
            bytes32 TMP_Hash = keccak256(abi.encodePacked(Resources[i]));   // Generate hash of the resource name
            RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Name = Resources[i]; // Set resource name in role
            require(Resource_Permissions[i] < 4 && Resource_Permissions[i] > 0, "Resource permission incorrect"); // ensure permissions are between 1 and 3 (inclusive)

            if (Resource_Permissions[i] == 1)   // if role permission for resource is to allow reads
            {
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Read = true;
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Write = false;
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Execute = false;
            }
            else if (Resource_Permissions[i] == 2)  //  if role permission for resource is to allow writes
            {
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Read = true;
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Write = true;
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Execute = false;
            }
            else if (Resource_Permissions[i] == 3)  //  if role permission for resource is to allow executes
            {
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Read = true;
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Write = true;
                RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Permissions.Execute = true;
            }

            RBAC_Roles[Role_Hash].Allowed_Resources[TMP_Hash].Resource_Timestamp = block.timestamp; //  create timestamp relating to when resource was added 
            RBAC_Roles[Role_Hash].Allowed_Resources_Hash.push(TMP_Hash);    // store the hash of the allowed resource
        }

        RBAC_Roles[Role_Hash].Allowed_Resources_Count = Resources.length;   // store number of resources allowed by the role
        Index_Role++; //increment number of roles
        Roles.push(Role_Hash); //store the generated hash of the role
    }


    /*Remove role from the smart contract, takes the name of the role to remove*/
    function Remove_Role(string memory Role) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender)); //ensure function is only executed by an Admin
        bytes32 Role_Hash = keccak256(abi.encodePacked(Role)); //generate keccak256 hash of role name
        require(RBAC_Roles[Role_Hash].Role_Timestamp != 0, "Role Does Not Exists"); //ensure that the role exists

        delete RBAC_Roles[Role_Hash]; //delete role from RBAC_Roles
        Index_Role--; //decrement number of roles
    }

    /*add user to the smart contract, takes the address of the user, the role to be assigned to the user, and information about the user*/
    function Add_User(address User_Address, string memory Role, string memory Information) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender)); //ensure admin is executing the function
        require(Users_Info[User_Address].User_Joined == 0, "User Exists"); //ensure the user doesn't already exist
        bytes32 Role_Hash = keccak256(abi.encodePacked(Role)); //generate the keccak256 hash of the user role
        require(RBAC_Roles[Role_Hash].Role_Timestamp != 0, "Role Does Not Exist");

        //initialise the user structure and store it within Users_Info
        Users_Info[User_Address].User_Role_Hash.push(Role_Hash);
        Users_Info[User_Address].User_Role_Count = 1;
        Users_Info[User_Address].Monitor_Behavior = Init_Monitoring;
        Users_Info[User_Address].User_Information = Information;
        Users_Info[User_Address].User_Joined = block.timestamp;
        Users_Info[User_Address].User_Index = Index_User;

        Index_User++;   //increment the number of users in the system
        Users.push(User_Address);   //store the user address hash
        grantRole(Role_Hash, User_Address); //utilise Openzeplin's AccessControl to grant user role
    }

    function Add_Additional_Roles_To_User(address User_Address, string memory Role) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender)); //ensure admin is executing the function
        require(Users_Info[User_Address].User_Joined != 0, "User Does Not Exists"); //ensure the user exists
        bytes32 Role_Hash = keccak256(abi.encodePacked(Role));
        require(RBAC_Roles[Role_Hash].Role_Timestamp != 0, "Role Does Not Exists"); // ensure the role exists

        for (uint256 i = 0; i < Users_Info[User_Address].User_Role_Count; i++) //   for each user role
        {
            require(Users_Info[User_Address].User_Role_Hash[i] != Role_Hash, "User Already Assigned this Role");    //  ensure user is not already assigned the role
        }
        
        Users_Info[User_Address].User_Role_Hash.push(Role_Hash);    // store role against the user
        Users_Info[User_Address].User_Role_Count++;     //  increment the number of roles assigned to the user
        grantRole(Role_Hash, User_Address); // grant the user the role
    }

    /*Remove roles from the user, takes the user address and a string role*/
    function Remove_Roles_From_User(address User_Address, string memory Role) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));
        require(Users_Info[User_Address].User_Joined != 0, "User Does Not Exists"); //ensure the user exists

        bytes32 Role_Hash = keccak256(abi.encodePacked(Role));
        require(RBAC_Roles[Role_Hash].Role_Timestamp != 0, "Role Does Not Exists"); // ensure the role exists

        bool Role_Found = false;
        uint256 i = 0;

        for (i; i<Users_Info[User_Address].User_Role_Count; i++) // for each role assigned to the user
        {
            if (Users_Info[User_Address].User_Role_Hash[i] == Role_Hash)    // check role hash against hash to be removed
            {
                Role_Found = true;  // role has been found
                break;  // break for loop
            }
        }

        require(Role_Found, "User not assigned to role");   //  ensure that the role has been found
        revokeRole(Users_Info[User_Address].User_Role_Hash[i], User_Address);   //  revoke role from user
        delete Users_Info[User_Address].User_Role_Hash[i];  //  remove role from users roles

        Users_Info[User_Address].User_Role_Count--;        
    }

    /*remove user from the smart contract, takes the address of the user*/
    function Remove_User(address User_Address) public 
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));   //ensure that only the admin can execute the function
        require(Users_Info[User_Address].User_Joined != 0, "User Does Not Exist"); //ensure that the user exists

        for (uint256 i=0; i < Users_Info[User_Address].User_Role_Count; i++) // for each role assigned to user
        {
            bytes32 User_Role = Users_Info[User_Address].User_Role_Hash[i]; //generate the keccak256 hash of the user role
            revokeRole(User_Role, User_Address);    //utilise Openzepplins AccessControl to revoke the users role
        }
        
        delete Users_Info[User_Address];    //delete user from User_Info
        Index_User--;   //decrement the number of users
    }

    /*Configure system that users can access, takes the name of the system, the role required to access the system, and information about the system*/
    function Configure_System(string memory System_Name_Add, string memory System_Information_Add, string[] memory Resource_Name) public 
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));   //ensure only an Admin can execute the function
        bytes32 System_Hash = keccak256(abi.encodePacked(System_Name_Add)); //generate keccak256 hash of system name
        require(Systems[System_Hash].System_Added == 0, "System Exists");   //ensure that the system does not exist
        uint256 i = 0;

        //initialise system struct and save it to systems
        Systems[System_Hash].System_Role_Count = 0;
        Systems[System_Hash].System_Information = System_Information_Add;
        Systems[System_Hash].System_Added = block.timestamp;
        Systems[System_Hash].System_Index = Index_System;

        for (i ; i < Resource_Name.length; i++) // for each resource assigned to the system
        {
            bytes32 Resource_Hash = keccak256(abi.encodePacked(Resource_Name[i]));  // Generate hash of the resource name
            Systems[System_Hash].System_Resources[Resource_Hash].Resource_Name = Resource_Name[i];  // store the name of the resource
            Systems[System_Hash].System_Resources[Resource_Hash].Resource_Timestamp = block.timestamp;  //   store the timestamp of the resource
        }

        Systems[System_Hash].System_Resource_Count = i; // store the number of resources in the system


        Index_System++; //increment the number of systems
        Systems_Arr.push(System_Hash); //store the system name hash
    }

    

    /*Remove a system from the smart contact, takes the name of the system to remove*/
    function Remove_System(string memory System_Name_Remove) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender)); //ensure only an admin can execute the function
        bytes32 System_Hash = keccak256(abi.encodePacked(System_Name_Remove)); //generate the keccak256 hash of the system name
        require(Systems[System_Hash].System_Added != 0, "System Does Not Exists");  //ensure that the system exists

        delete Systems[System_Hash];    //delete system
        Index_System--; //decrement number of systems
    }




    /*------------------------Assign Roles to Systems---------------------------------*/

    function Assign_Role_To_System(string memory Role, string memory System) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));   //ensure only an Admin can execute the function
        
        bytes32 Role_Hash = keccak256(abi.encodePacked(Role));    //generate keccak256 hash of the role required to access the system
        require(RBAC_Roles[Role_Hash].Role_Timestamp != 0, "Role Does Not Exist");  //ensure that the role exists
        bytes32 System_Hash = keccak256(abi.encodePacked(System));
        require(Systems[System_Hash].System_Added != 0, "System Does Not Exists"); //ensure the system exists


        for (uint256 i = 0; i<RBAC_Roles[Role_Hash].Allowed_Resources_Count; i++) //    for the number of resources allowed by the user roles
        {
            require(Systems[System_Hash].System_Resources[RBAC_Roles[Role_Hash].Allowed_Resources_Hash[i]].Resource_Timestamp != 0, "Resource in Role does not exist within system");   // ensure that each resource allowed by the role is assigned to the system
        }

        Systems[System_Hash].Required_Role_Hash.push(Role_Hash);    // add the role to the system
        Systems[System_Hash].System_Role_Count++;   // increment the number of roles assigned to the system

    }


    /*---------------------------User Access Monitoring---------------------------------*/

    //function for users to request access to systems, takes the system a user wishes to access
    function User_Request_Access(string memory Access_Request) public returns (bool Access)
    {
        Access = false; //assume that user cannot access system until the opposite is proven
        bool role = false;
        address User_Add = msg.sender;  //retreive the address of the user
        bytes32 Role_Test;

        require(Users_Info[User_Add].User_Joined != 0, "User Does Not Exist"); //ensure that the user exists within the system
        bytes32 System_Hash = keccak256(abi.encodePacked(Access_Request));  //generate system name hash of the requested system
        require(Systems[System_Hash].System_Added != 0, "Requested System Does Not Exist"); //ensure requested system exists
        bytes32[] memory Role_Hash = new bytes32[](Systems[System_Hash].System_Role_Count);

        if (Users_Info[User_Add].Monitor_Behavior.Resource_Request_Fail)
        {
            Access_Request_Deny(User_Add, Access_Request);   //evaluate user access to the system
            Users_Info[User_Add].Monitor_Behavior.Resource_Request_Fail = false;
        }       
       
        if (Users_Info[User_Add].Monitor_Behavior.User_Restricted == true)  // check if the users access is restricted
        {
            return Access;  // User cannot access the system
        }

        for (uint i = 0; i< Systems[System_Hash].System_Role_Count; i++) 
        {
            Role_Test = Systems[System_Hash].Required_Role_Hash[i];
            role = hasRole(Role_Test, User_Add); //utilise Openzepplins AccessControl to ensure user has required role
            if (role)
            {
                // If the role exists
                if (RBAC_Roles[Role_Test].Role_Timestamp != 0)
                {
                    Role_Hash[i] = Role_Test;
                }
                else 
                {
                    //found role does not exist
                    role = false;
                }
            }
        }       
        
        if (!role)   //if the user does not have the required role
        {
            Access_Request_Deny(User_Add, Access_Request);   //evaluate user access to the system
            return Access;
        }

        
        if (Users_Info[User_Add].Monitor_Behavior.Prev_Request_Fail)
        {
            Users_Info[User_Add].Monitor_Behavior.Prev_Request_Fail = false; //set the user previous request was successful
        }

        Generate_RBAC_Session(System_Hash, User_Add, Role_Hash); //Generate session for user to access system
        Access = true;  //decide the user can access the system
        return Access;  //User can access the system
    }

    //evaluate the user access to the system, takes the user address and the system requested
    function Access_Request_Deny(address User_Add, string memory Requested_System) private
    {
        if (Users_Info[User_Add].Monitor_Behavior.Request_Deny_Count > 2)   //if a user has had 3 failed system requests
        {
            //restrict the user
            Users_Info[User_Add].Monitor_Behavior.User_Suspended_Count++;
            Block_User_Abuse(User_Add, Requested_System);
        }
        else 
        {
            Users_Info[User_Add].Monitor_Behavior.Request_Deny_Count++; //  increment the number of denyed requests by the system
            Users_Info[User_Add].Monitor_Behavior.Last_Request_Time = block.timestamp;  //  store the time at which the user attempted the request
            Users_Info[User_Add].Monitor_Behavior.Prev_Request_Fail = true; //  set the previous request failiure to true
        }
    }


    //block the user from accessing the system, takes the role they requested, the system they requested, and the user address
    function Block_User_Abuse(address User_Add, string memory Requested_System) private
    {

        Users_Info[User_Add].Monitor_Behavior.User_Restricted = true;   //set user restriced to true
        string memory Role_String = Create_User_Role_String(User_Add);  // create user role string to be used in logging
        string memory System_Role_String = Create_System_Role_String(Requested_System); //  create system role string to be used in logging

        string memory Abuse = string(abi.encodePacked(
            Strings.toString(block.timestamp),",",
            Strings.toHexString(uint256(uint160(User_Add)), 20),",",
            Role_String,",",
            System_Role_String,",",
            Requested_System,",",
            Users_Info[User_Add].Monitor_Behavior.Last_Requested_Resource,",",
            Strings.toString(Users_Info[User_Add].Monitor_Behavior.User_Suspended_Count),";")); //generate log for SOC team
        Abuse_Log.push(Abuse);  // store log
    }

    ////LOG STRING CREATAION

    function Create_User_Role_String(address User_Add) private view returns (string memory Role_String)
    {
        Role_String = "{";
        uint i;
        for (i = 0; i < Users_Info[User_Add].User_Role_Count; i++) 
        {
            Role_String = string(abi.encodePacked(Role_String,RBAC_Roles[Users_Info[User_Add].User_Role_Hash[i]].Role_Name,":"));
        }

        uint str_len = bytes(Role_String).length;
        bytes(Role_String)[str_len-1] = bytes1("}"); //Test THIS
        return Role_String;
    }

    function Create_System_Role_String(string memory System) private view returns (string memory Role_String)
    {
        Role_String = "{";
        uint i;
        bytes32 System_Hash = keccak256(abi.encodePacked(System));

        for (i = 0; i < Systems[System_Hash].System_Role_Count; i++) 
        {
            Role_String = string(abi.encodePacked(Role_String,RBAC_Roles[Systems[System_Hash].Required_Role_Hash[i]].Role_Name,":"));
        }

        uint str_len = bytes(Role_String).length;
        bytes(Role_String)[str_len - 1] = bytes1("}"); //Test This
        return Role_String;
    }

    //END LOG STRING CREATION

    /*---------------------------End User Access Monitoring------------------------------*/

    /**********************************RBAC Sessions***************************************/

    //Create an RBAC session when a user is authenticated against a system, takes the hash of the system being accessed, 
    //the address of the user, and the hash of the role being used within the sesison
    function Generate_RBAC_Session(bytes32 System_Hash, address User_Add, bytes32[] memory Role_Hash) private
    {
        require(User_Sessions[User_Add].Session_Init_Time == 0, "Session Already exists for this user");

        //  initalise new user session
        User_Sessions[User_Add].Session_Role_Hash = Role_Hash;
        User_Sessions[User_Add].Session_Init_Time = block.timestamp;
        User_Sessions[User_Add].System_Hash = System_Hash;
        User_Sessions[User_Add].Session_Index = Index_Session;

        Index_Session++;    //  increment number of active sessions
    }

    //Terminate the RBAC session generated by the user, takes no arguments
    function Terminate_RBAC_Session() public
    {
        address User_Add = msg.sender;
        require(User_Sessions[User_Add].Session_Init_Time != 0, "No session for this user");

        delete User_Sessions[User_Add];

        Index_Session--;

    }

    //Request access to a system resource, takes the resource to be accessed and the permissions to access the resource with
    function Resource_Access(string memory Resource, uint256 Requested_Permissions) public returns (bool Access)
    {
        address User_Add = msg.sender;
        require(User_Sessions[User_Add].Session_Init_Time != 0, "No session for this user");    //  ensure user has a sesison assigned to them
        bytes32 Requested_Resource_Hash = keccak256(abi.encodePacked(Resource));    //  generate hash of the requirested resource
        require(Systems[User_Sessions[User_Add].System_Hash].System_Resources[Requested_Resource_Hash].Resource_Timestamp != 0,"Requested Resource Does Not Exist On This System"); // ensure resource exists on the system
        bytes32 Session_Hash_Role;

        for (uint256 i = 0; i<User_Sessions[User_Add].Session_Role_Hash.length; i++) //for the number of roles attributed to the session
        {
            Session_Hash_Role = User_Sessions[User_Add].Session_Role_Hash[i];
            // if the requested resource is allowed by the RBAC role
            if (RBAC_Roles[Session_Hash_Role].Allowed_Resources[Requested_Resource_Hash].Resource_Timestamp != 0)   
            {   
                // if the permisions of the rbac role allow the user to perform read against this resource AND the user requests to read the resource
                if ((Requested_Permissions == 1) && (RBAC_Roles[Session_Hash_Role].Allowed_Resources[Requested_Resource_Hash].Resource_Permissions.Read))   
                {
                    return true;    //  enable the user to read the resource
                }
                // if the permisions of the rbac role allow the user to perform write against this resource AND the user requests to write to the resource
                else if ((Requested_Permissions == 2) && (RBAC_Roles[Session_Hash_Role].Allowed_Resources[Requested_Resource_Hash].Resource_Permissions.Write)) 
                {
                    return true;    // enable the user to write to the resource
                }
                // if the permisions of the rbac role allow the user to perform executes against this resource AND the user requests to execute the resource
                else if ((Requested_Permissions == 3) && (RBAC_Roles[Session_Hash_Role].Allowed_Resources[Requested_Resource_Hash].Resource_Permissions.Execute)) 
                {
                    return true;    //  enable the user to execute the resource
                }
            }

        }
        //after every role is checked for the required permissions, and they are unsucessful, begin user monitoring 
        Users_Info[User_Add].Monitor_Behavior.Request_Deny_Count++; //  increment the number of denyied requests
        Users_Info[User_Add].Monitor_Behavior.Last_Requested_Resource = Systems[User_Sessions[User_Add].System_Hash].System_Resources[Requested_Resource_Hash].Resource_Name;
        Users_Info[User_Add].Monitor_Behavior.Resource_Request_Fail = true;
        Terminate_RBAC_Session();
        return false;
    }



    /**********************************End RBAC Session************************************/






    /*----------------------------SOC Team Functionality---------------------------------*/

    //set up the Security Operations Centre account, takes the address of the SOC account
    function Set_Up_SOC(address SOC_Add) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));   //ensure only the admin can assign a SOC user
        grantRole(SOC_Role, SOC_Add);                       //grant the account the role of SOC
    }

    //remove a Security Operations Centre account, takes the address of the SOC account to remove
    function Remove_SOC(address SOC_Add) public
    {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));
        require(hasRole(SOC_Role, SOC_Add));

        revokeRole(SOC_Role, SOC_Add);
    }

    //return the logs generated by the access monitoring
    function Return_Abuse_Log() public returns (string[] memory)
    {
        require(hasRole(SOC_Role, msg.sender)); //ensure only the SOC role can retreive logs
        string[] memory tmp_Abuse_Log = Abuse_Log;  //store the logs in a temporary variable

        for (uint256 i = 0; i<Abuse_Log.length; i++) // for the number of logs within the array of logs
        {
            Abuse_Log.pop();    //remove log
        }

        return tmp_Abuse_Log;   //return logs to SOC
    }

    //enable the soc to reinitalise a user account, takes the address of the user to reinitalise
    function Soc_REINIT_User(address User_Add) public
    {
        require(hasRole(SOC_Role, msg.sender)); //ensure only the SOC role can execute the function

        //reset users monitoring information
        Users_Info[User_Add].Monitor_Behavior.Prev_Request_Fail = false;
        Users_Info[User_Add].Monitor_Behavior.Request_Deny_Count = 0;

        //enable users to access system
        Users_Info[User_Add].Monitor_Behavior.User_Restricted = false;
    }

}

/*----------------------------End SOC Team Functionality---------------------------------*/