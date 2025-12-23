#include <stdio.h>
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_USERNAME_LEN 20
#define MAX_PASSWORD_LEN 32
#define MAX_HASH_LEN 65
#define MAX_SALT_LEN 33
#define MAX_Q_LEN 100
#define MAX_A_LEN 50
#define MAX_ATTEMPTS 3
#define LOCKOUT_DURATION 15
#define MAX_LINE_LEN 512

typedef struct User {
    char username[MAX_USERNAME_LEN + 1];
    char password_hash[MAX_HASH_LEN];
    char salt[MAX_SALT_LEN];
    char security_question[MAX_Q_LEN];
    char security_answer_hash[MAX_HASH_LEN];
    int failed_attempts;
    time_t lockout_until;
    struct User *next;
} User;

User *head = NULL;
const char *DATA_FILE = "user_data.txt";
const char *LOG_FILE = "auth.log";

// Function Prototypes
void load_data();
void save_data();
void log_event(const char *username, const char *event_type, const char *message);
void generate_salt(char *salt);
void hash_with_salt(const char *input, const char *salt, char *hash);
int check_password_strength(const char *password);
User *find_user(const char *username);
void register_user();
void authenticate_user();
void recover_password();
void change_security_question();
void view_logs();
void list_users();
void delete_user();
void main_menu();
void cleanup_memory();


// Logging
void log_event(const char *username, const char *event_type, const char *message) {
    FILE *file = fopen(LOG_FILE, "a");
    if (!file) return;

    time_t t = time(NULL);
    char buffer[32];
    struct tm *tm_info = localtime(&t);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(file, "[%s] User:%s | %s | %s\n", buffer, username, event_type, message);
    fclose(file);
}

// Salt generator
void generate_salt(char *salt) {
    for (int i = 0; i < 16; i++)
        sprintf(&salt[i * 2], "%02x", rand() % 256);

    salt[32] = '\0';
}

// Hash simulation
void hash_with_salt(const char *input, const char *salt, char *hash) {
    unsigned long long sum = 0;
    for (int i = 0; input[i]; i++)
        sum += input[i];

    unsigned long long salt_val = 0;
    sscanf(salt, "%llx", &salt_val);

    unsigned long long mix = sum ^ salt_val;

    sprintf(hash, "%016llx%016llx%016llx%016llx", mix, sum, salt_val, mix);
    hash[64] = '\0';
}

// Password strength verification
int check_password_strength(const char *password) {
    int upper = 0, lower = 0, digit = 0, special = 0;

    if (strlen(password) < 8)
        return 0;

    for (int i = 0; password[i]; i++) {
        if (isupper(password[i])) upper = 1;
        else if (islower(password[i])) lower = 1;
        else if (isdigit(password[i])) digit = 1;
        else special = 1;
    }
    return upper && lower && digit && special;
}

User *find_user(const char *username) {
    User *curr = head;
    while (curr) {
        if (strcmp(curr->username, username) == 0)
            return curr;
        curr = curr->next;
    }
    return NULL;
}


// Save database to file
void save_data() {
    FILE *file = fopen(DATA_FILE, "w");
    if (!file) {
        printf("🚨 Error opening database.\n"); // EMOJI ADDED
        return;
    }

    User *u = head;
    while (u) {
        fprintf(file, "%s|%s|%s|%s|%s|%d|%ld\n",
                u->username, u->password_hash, u->salt,
                u->security_question, u->security_answer_hash,
                u->failed_attempts, (long)u->lockout_until);
        u = u->next;
    }
    fclose(file);
}


// Load users from file
void load_data() {
    FILE *file = fopen(DATA_FILE, "r");
    if (!file) return;

    cleanup_memory();

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        User *u = malloc(sizeof(User));
        if (!u) break;

        int fa;
        long lo;
        sscanf(line, "%20[^|]|%64[^|]|%32[^|]|%99[^|]|%64[^|]|%d|%ld",
               u->username, u->password_hash, u->salt,
               u->security_question, u->security_answer_hash,
               &fa, &lo);

        u->failed_attempts = fa;
        u->lockout_until = (time_t)lo;
        u->next = head;
        head = u;
    }
    fclose(file);
}


// Memory cleanup
void cleanup_memory() {
    User *curr = head, *next;
    while (curr) {
        next = curr->next;
        memset(curr, 0, sizeof(User));
        free(curr);
        curr = next;
    }
    head = NULL;
}


// Register new user
void register_user() {
    char username[30], password[40], q[MAX_Q_LEN], a[MAX_A_LEN];

    printf("\n--- New User Registration 📝 ---\n");
    printf("➡️ Enter username: ");
    scanf("%20s", username);

    if (find_user(username)) {
        printf("❌ User already exists.\n");
        return;
    }

    do {
        printf("➡️ Enter strong password: ");
        scanf("%32s", password);
        if (!check_password_strength(password))
            printf("⚠️ Weak password! Must include uppercase, lowercase, digit, special chars.\n");
    } while (!check_password_strength(password));

    getchar();
    printf("➡️ Enter security question: ");
    fgets(q, sizeof(q), stdin);
    q[strcspn(q, "\n")] = 0;

    printf("➡️ Enter answer: ");
    fgets(a, sizeof(a), stdin);
    a[strcspn(a, "\n")] = 0;

    // 🔥 IMPORTANT VALIDATION YOU WANTED
    if (strcmp(q, a) != 0) {
        printf("❌ Registration failed! Question and Answer must be EXACTLY SAME.\n");
        return;  // stop registration
    }

    // Allocate and store user only when validation passed
    User *u = malloc(sizeof(User));
    strcpy(u->username, username);

    generate_salt(u->salt);

    hash_with_salt(password, u->salt, u->password_hash);
    hash_with_salt(a, u->salt, u->security_answer_hash);

    memset(password, 0, sizeof(password));
    memset(a, 0, sizeof(a));

    u->failed_attempts = 0;
    u->lockout_until = 0;

    u->next = head;
    head = u;

    save_data();
    log_event(username, "REGISTER", "New user created.");
    printf("✅ User registered successfully.\n");
}

// Authentication + OTP
void authenticate_user() {
    char username[30], password[40], temp_hash[70], otp_gen[7], otp_input[10];

    printf("\n--- User Login 🔑 ---\n"); // EMOJI ADDED
    printf("➡️ Enter username: "); // EMOJI ADDED
    scanf("%20s", username);

    User *u = find_user(username);
    if (!u) {
        printf("❌ User not found.\n"); // EMOJI ADDED
        sleep(1);
        return;
    }

    if (u->lockout_until > time(NULL)) {
        printf("🔒 Account locked for %ld seconds.\n", (long)(u->lockout_until - time(NULL))); // EMOJI ADDED
        return;
    }

    printf("➡️ Enter password: "); // EMOJI ADDED
    scanf("%32s", password);
    hash_with_salt(password, u->salt, temp_hash);
    memset(password, 0, sizeof(password));

    if (strcmp(temp_hash, u->password_hash) != 0) {
        u->failed_attempts++;
        if (u->failed_attempts >= MAX_ATTEMPTS) {
            u->lockout_until = time(NULL) + LOCKOUT_DURATION;
            printf("🛑 Account locked.\n"); // EMOJI ADDED
            log_event(username, "LOCKOUT", "Too many attempts.");
        } else {
            printf("⚠️ Incorrect password. Attempts left: %d\n", MAX_ATTEMPTS - u->failed_attempts); // EMOJI ADDED
        }
        save_data();
        return;
    }

    // OTP validation with 3 attempts
    int otp_attempts = 3;
    sprintf(otp_gen, "%06d", rand() % 900000 + 100000);

    while (otp_attempts--) {
        printf("\n[Simulated OTP Sent] 📧 -> %s\n➡️ Enter OTP: ", otp_gen);
        scanf("%6s", otp_input);

        if (strcmp(otp_gen, otp_input) == 0) {
            printf("✅ Login successful! Welcome %s. 🚀\n", username);
            log_event(username, "LOGIN", "Login success.");
            memset(otp_gen, 0, sizeof(otp_gen));
            memset(otp_input, 0, sizeof(otp_input));
            return;  // login complete
        }

        if (otp_attempts)
            printf("❌ Wrong OTP! Attempts left: %d\n", otp_attempts);
    }

    printf("❌ OTP verification failed. Please try login again.\n");
    memset(otp_gen, 0, sizeof(otp_gen));
    memset(otp_input, 0, sizeof(otp_input));
    return;

}


// Password recovery
void recover_password() {
    char username[30], ans[MAX_A_LEN], ans_hash[70], new_pass[40];

    printf("\n--- Password Recovery ♻️ ---\n"); // EMOJI ADDED
    printf("➡️ Enter username: "); // EMOJI ADDED
    scanf("%20s", username);

    User *u = find_user(username);
    if (!u) {
        printf("❌ User not found.\n"); // EMOJI ADDED
        return;
    }

    printf("❓ Security Question: %s\n", u->security_question); // EMOJI ADDED
    getchar();
    printf("➡️ Answer: "); // EMOJI ADDED
    fgets(ans, sizeof(ans), stdin);
    ans[strcspn(ans, "\n")] = 0;

    hash_with_salt(ans, u->salt, ans_hash);

    if (strcmp(ans_hash, u->security_answer_hash) != 0) {
        printf("❌ Incorrect answer.\n"); // EMOJI ADDED
        return;
    }

    do {
        printf("➡️ Enter new password: "); // EMOJI ADDED
        scanf("%32s", new_pass);
    } while (!check_password_strength(new_pass));

    generate_salt(u->salt);
    hash_with_salt(new_pass, u->salt, u->password_hash);
    memset(new_pass, 0, sizeof(new_pass));

    save_data();
    printf("✅ Password reset success.\n"); // EMOJI ADDED
}


// Security Q change
void change_security_question() {
    char username[30], password[40], pass_hash[70], q[MAX_Q_LEN], a[MAX_A_LEN];

    printf("\n--- Change Security Question 🛠️ ---\n"); // EMOJI ADDED
    printf("➡️ Username: "); // EMOJI ADDED
    scanf("%20s", username);

    User *u = find_user(username);
    if (!u) {
        printf("❌ User not found.\n"); // EMOJI ADDED
        return;
    }

    printf("➡️ Password: "); // EMOJI ADDED
    scanf("%32s", password);
    hash_with_salt(password, u->salt, pass_hash);
    memset(password, 0, sizeof(password));

    if (strcmp(pass_hash, u->password_hash) != 0) {
        printf("❌ Incorrect password.\n"); // EMOJI ADDED
        return;
    }

    getchar();
    printf("➡️ New security question: "); // EMOJI ADDED
    fgets(q, sizeof(q), stdin);
    q[strcspn(q, "\n")] = 0;

    printf("➡️ New answer: "); // EMOJI ADDED
    fgets(a, sizeof(a), stdin);
    a[strcspn(a, "\n")] = 0;

    strcpy(u->security_question, q);
    hash_with_salt(a, u->salt, u->security_answer_hash);

    save_data();
    printf("✅ Security question updated.\n"); // EMOJI ADDED
}


// User list
void list_users() {
    printf("\n--- User List 👥 ---\n"); // EMOJI ADDED
    if (!head) {
        printf("ℹ️ No users.\n"); // EMOJI ADDED
        return;
    }

    User *u = head;
    while (u) {
        printf("👤 - %s\n", u->username); // EMOJI ADDED
        u = u->next;
    }
}


// Delete user
void delete_user() {
    char username[30], file_user[30], file_pass[50];
    int found = 0;
    int ch;

    // Clear input buffer
    while ((ch = getchar()) != '\n' && ch != EOF);

    printf("\n--- Delete User ---\n");
    printf("➡️ Enter username to delete: ");

    fgets(username, sizeof(username), stdin);

    username[strcspn(username, "\n")] = '\0';

    if(strlen(username) == 0) {
        printf("⚠️ Username cannot be empty! Please enter a valid name.\n");
        return;
    }

    FILE *src = fopen("users.txt", "r");
    if (!src) {
        printf("❌ No user database found.\n");
        return;
    }

    FILE *temp = fopen("temp.txt", "w");
    if (!temp) {
        fclose(src);
        printf("❌ Failed to create temp file.\n");
        return;
    }

    while (fscanf(src, "%s %s", file_user, file_pass) != EOF) {
        if (strcmp(file_user, username) != 0) {
            fprintf(temp, "%s %s\n", file_user, file_pass);
        } else {
            found = 1;
        }
    }

    fclose(src);
    fclose(temp);

    remove("users.txt");
    rename("temp.txt", "users.txt");

    if (found) {
        printf("✔️ User '%s' deleted successfully!\n", username);
    } else {
        printf("❌ User '%s' not found in database.\n", username);
    }

}


// Menu system
void main_menu() {
    int ch;
    do {
        printf("\n==== USER AUTHENTICATION MODULE ⚙️ ====\n");
        printf("1. Register New User: \n");
        printf("2. Login (2FA): \n");
        printf("3. Recover Password: \n");
        printf("4. Change Security Question: \n");
        printf("5. View all Logs: \n");
        printf("6. List all Users: \n");
        printf("7. Delete User: \n");
        printf("8. Exit\n");
        printf("➡️ Select Option From 1 to 8: ");

        if (scanf("%d", &ch) != 1) {
            printf("❌ Invalid input! Please enter a number between 1-8.\n");

            while (getchar() != '\n'); // Clear invalid text
            continue; // Restart loop safely
        }

        switch (ch) {
            case 1: register_user(); break;
            case 2: authenticate_user(); break;
            case 3: recover_password(); break;
            case 4: change_security_question(); break;
            case 5: view_logs(); break;
            case 6: list_users(); break;
            case 7: delete_user(); break;
            case 8: printf("👋 Goodbye.\n"); break;
            default: printf("❌ Invalid choice. Please select 1 to 8.\n");
        }

    } while (ch != 8);
}



int main() {
    srand(time(NULL));
    load_data();
    main_menu();
    cleanup_memory();
    return 0;
}

void view_logs() {
    FILE *file = fopen(LOG_FILE, "r");
    if (!file) {
        printf("ℹ️ No logs.\n"); // EMOJI ADDED
        return;
    }
    printf("\n--- System Log 📜 ---\n"); // EMOJI ADDED
    char line[200];
    while (fgets(line, sizeof(line), file))
        printf("%s", line);
    fclose(file);
}
