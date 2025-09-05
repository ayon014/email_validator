import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import pandas as pd
import requests
import csv
import os

API_KEY = "f4488df31e8e4cf70b779feb674c23f146adf30d23f3923503b4584bfe6b"
MAX_FREE_EMAILS = 100  # Free plan limit

class EmailValidatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bulk Email Validator")
        self.root.geometry("750x600")
        self.root.resizable(True, True)
        self.setup_ui()
        
    def setup_ui(self):
        # Main container frame for better layout control
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File selection
        ttk.Label(main_frame, text="Select CSV or Excel file with emails:", font=("Arial", 10)).pack(pady=5)
        
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=60, state="readonly").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT)

        # Validate button
        ttk.Button(main_frame, text="Validate Emails", command=self.validate_emails).pack(pady=10)

        # Progress bar with label
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, text="Progress:").pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(progress_frame, mode='determinate', length=500)
        self.progress.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)

        # Log area
        ttk.Label(main_frame, text="Validation Log:", font=("Arial", 10)).pack(pady=(10, 5))
        self.log_text = scrolledtext.ScrolledText(main_frame, width=85, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select email file",
            filetypes=[("CSV files", "*.csv"), ("Excel files", "*.xlsx *.xls"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.status_var.set(f"Selected: {os.path.basename(file_path)}")
    
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()

    def read_emails(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            df = pd.read_csv(file_path)
        elif ext in [".xlsx", ".xls"]:
            df = pd.read_excel(file_path)
        else:
            raise ValueError("Unsupported file type. Please use CSV or Excel files.")
        
        # Try to detect email column
        email_col = next((col for col in df.columns if any(keyword in col.lower() for keyword in ['email', 'e-mail', 'mail'])), df.columns[0])
        emails = df[email_col].dropna().astype(str).tolist()
        
        if len(emails) > MAX_FREE_EMAILS:
            self.log(f"Note: Only processing first {MAX_FREE_EMAILS} emails (free plan limit)")
            
        return emails[:MAX_FREE_EMAILS]

    def validate_email(self, email):
        url = f"https://api.quickemailverification.com/v1/verify?email={email}&apikey={API_KEY}"
        try:
            resp = requests.get(url, timeout=20)
            
            # Check if response is valid before parsing as JSON
            if resp.status_code != 200:
                return "error", f"API Error: HTTP {resp.status_code}"
                
            data = resp.json()
            return data.get("result", "unknown"), data.get("reason", "No reason provided")
            
        except requests.exceptions.Timeout:
            return "timeout", "Request timed out"
        except requests.exceptions.ConnectionError:
            return "error", "Connection error - check your internet"
        except Exception as e:
            return "error", str(e)

    def save_results(self, results):
        valid = [e for e, (s, _) in results.items() if s == "valid"]
        invalid = [e for e, (s, _) in results.items() if s != "valid"]

        try:
            with open("valid_emails.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Email", "Status"])
                writer.writerows([[e, "valid"] for e in valid])
        
            with open("invalid_emails.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Email", "Status", "Reason"])
                writer.writerows([[e, results[e][0], results[e][1]] for e in invalid])
        
            return len(valid), len(invalid)
        except Exception as e:
            raise Exception(f"Failed to save results: {str(e)}")

    def validate_emails(self):
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
        
        # Disable validate button during processing
        self.validate_button_state = tk.DISABLED
        
        try:
            emails = self.read_emails(file_path)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        if not emails:
            messagebox.showwarning("Warning", "No valid emails found in the selected file")
            return

        self.log_text.delete(1.0, tk.END)
        self.log(f"Processing {len(emails)} emails...")
        self.progress['maximum'] = len(emails)
        self.progress['value'] = 0

        results = {}
        for i, email in enumerate(emails, 1):
            self.update_status(f"Processing {i}/{len(emails)}: {email}")
            status, reason = self.validate_email(email)
            results[email] = (status, reason)
            self.log(f"{i}. {email} -> {status} ({reason})")
            self.progress['value'] = i
            self.root.update_idletasks()
            self.root.after(100)  # Small delay to avoid overwhelming API

        try:
            valid_count, invalid_count = self.save_results(results)
            self.log(f"Validation complete! Valid: {valid_count}, Invalid: {invalid_count}")
            self.update_status("Validation complete - results saved to CSV files")
            
            messagebox.showinfo("Done", 
                f"Validation complete!\n"
                f"Valid: {valid_count}\n"
                f"Invalid: {invalid_count}\n\n"
                f"Files saved as:\n"
                f"- valid_emails.csv\n"
                f"- invalid_emails.csv")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")
        
        # Re-enable validate button
        self.validate_button_state = tk.NORMAL

def main():
    root = tk.Tk()
    app = EmailValidatorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()