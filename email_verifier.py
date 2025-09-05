import re
import dns.resolver
import asyncio
import aiohttp
import aiodns
import time
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Dict, Optional, Set, Tuple
import openpyxl
from tqdm import tqdm
from dataclasses import dataclass
import json
from concurrent.futures import ThreadPoolExecutor
import socket


@dataclass
class VerificationResult:
    email: str
    is_valid: bool
    reason: str
    method: str


class HunterEmailVerifier:
    def __init__(self, api_key: str = None,
                 strict_mode: bool = False, 
                 optimistic_mode: bool = True,
                 max_concurrent_tasks: int = 20):
        
        self.api_key = api_key
        self.strict_mode = strict_mode
        self.optimistic_mode = optimistic_mode
        
        self.valid_emails: Set[str] = set()
        self.invalid_emails: Set[str] = set()
        self.domain_analysis: Dict[str, Dict] = {}
        self.verification_results: List[VerificationResult] = []

        self.dns_resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.thread_pool = ThreadPoolExecutor(max_workers=10)

        self.EMAIL_REGEX = re.compile(
            r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@'
            r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$'
        )

        # Disposable domains list
        self.DISPOSABLE_DOMAINS = {
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            '10minutemail.com', 'yopmail.com', 'throwawaymail.com',
            'fakeinbox.com', 'temp-mail.org', 'trashmail.com',
            'dispostable.com', 'mailnesia.com', 'getairmail.com',
            'maildrop.cc', 'tempinbox.com', 'fake-mail.com',
            'mintemail.com', 'tempomail.org', 'jetable.org',
            'mailmetrash.com', 'trashmailer.com', 'disposable.com',
            'throwawayemail.com', 'tempemail.net'
        }

        # Corporate domain patterns
        self.CORPORATE_PATTERNS = [
            "edu", "ac.", "org", "gov", "bank", "university", "college",
            "institute", "school", "hospital", "corp", "inc", "ltd", "company",
            "enterprise", "business", "group", "holdings", "limited"
        ]

        # Hunter.io API configuration
        self.HUNTER_API_URL = "https://api.hunter.io/v2/email-verifier"
        
    def check_syntax(self, email: str) -> Tuple[bool, str]:
        """Check email syntax"""
        if not email or '@' not in email:
            return False, "No @ symbol found"
        
        if not self.EMAIL_REGEX.match(email):
            return False, "Invalid email format"
        
        return True, "Valid syntax"

    def check_disposable_domain(self, email: str) -> Tuple[bool, str]:
        """Check if email uses a disposable domain"""
        try:
            domain = email.split('@')[1].lower()
            if domain in self.DISPOSABLE_DOMAINS:
                return True, f"Disposable domain: {domain}"
            return False, "Not a disposable domain"
        except IndexError:
            return True, "Invalid domain format"

    def is_likely_corporate_domain(self, email: str) -> Tuple[bool, str]:
        """Check if domain is likely corporate"""
        try:
            domain = email.split('@')[1].lower()
            
            # Check for corporate patterns
            if any(pattern in domain for pattern in self.CORPORATE_PATTERNS):
                return True, "Corporate pattern detected"
                
            return False, "No corporate indicators found"
            
        except IndexError:
            return False, "Invalid email format"

    async def check_mx_records(self, domain: str) -> Tuple[bool, str]:
        """Check MX records"""
        try:
            mx_records = await self.dns_resolver.query(domain, 'MX')
            if mx_records:
                return True, f"MX records found: {len(mx_records)}"
            return False, "No MX records found"
        except Exception as e:
            return False, f"DNS error: {str(e)}"

    async def hunter_api_verify(self, email: str) -> Tuple[Optional[bool], str]:
        """Verify email using Hunter.io API"""
        if not self.api_key:
            return None, "Hunter.io API key not configured"

        try:
            params = {
                "email": email,
                "api_key": self.api_key
            }
            
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.HUNTER_API_URL, params=params) as response:
                    
                    if response.status == 401:
                        return None, "Invalid API key - please check your Hunter.io API key"
                    elif response.status == 402:
                        return None, "API quota exceeded - upgrade your Hunter.io plan"
                    elif response.status == 429:
                        return None, "Rate limit exceeded - too many requests"
                    elif response.status != 200:
                        return None, f"API error: HTTP {response.status}"
                    
                    data = await response.json()
                    
                    # Extract verification result from Hunter.io response
                    result = data.get("data", {}).get("result")
                    status = data.get("data", {}).get("status")
                    
                    if result == "deliverable":
                        return True, "Hunter.io: Deliverable email"
                    elif result == "undeliverable":
                        return False, "Hunter.io: Undeliverable email"
                    elif status == "invalid":
                        return False, "Hunter.io: Invalid email"
                    else:
                        return None, f"Hunter.io: Unknown status ({result})"
                        
        except asyncio.TimeoutError:
            return None, "Hunter.io API timeout"
        except aiohttp.ClientError as e:
            return None, f"Hunter.io API connection error: {str(e)}"
        except Exception as e:
            return None, f"Hunter.io API unexpected error: {str(e)}"

    async def verify_email(self, email: str) -> VerificationResult:
        """Complete email verification pipeline"""
        email = email.strip().lower()
        
        # Track domain statistics
        domain = email.split('@')[1] if '@' in email else "invalid"
        if domain not in self.domain_analysis:
            self.domain_analysis[domain] = {
                "total": 0, "valid": 0, "invalid": 0,
                "methods": {}, "reasons": {}
            }
        self.domain_analysis[domain]["total"] += 1

        # 1. Syntax check
        syntax_ok, syntax_reason = self.check_syntax(email)
        if not syntax_ok:
            self.domain_analysis[domain]["invalid"] += 1
            return VerificationResult(email, False, syntax_reason, "syntax")

        # 2. Disposable domain check
        is_disposable, disposable_reason = self.check_disposable_domain(email)
        if is_disposable:
            self.domain_analysis[domain]["invalid"] += 1
            return VerificationResult(email, False, disposable_reason, "disposable")

        # 3. Hunter.io API verification
        api_result, api_reason = await self.hunter_api_verify(email)
        if api_result is not None:
            if api_result:
                self.domain_analysis[domain]["valid"] += 1
                self.domain_analysis[domain]["methods"]["hunter"] = \
                    self.domain_analysis[domain]["methods"].get("hunter", 0) + 1
                return VerificationResult(email, True, api_reason, "hunter")
            else:
                self.domain_analysis[domain]["invalid"] += 1
                self.domain_analysis[domain]["methods"]["hunter"] = \
                    self.domain_analysis[domain]["methods"].get("hunter", 0) + 1
                return VerificationResult(email, False, api_reason, "hunter")

        # 4. Strict mode checks (MX records)
        if self.strict_mode:
            mx_ok, mx_reason = await self.check_mx_records(domain)
            if not mx_ok:
                self.domain_analysis[domain]["invalid"] += 1
                return VerificationResult(email, False, mx_reason, "mx")

        # 5. Optimistic mode for corporate domains
        if self.optimistic_mode:
            is_corporate, corporate_reason = self.is_likely_corporate_domain(email)
            if is_corporate:
                self.domain_analysis[domain]["valid"] += 1
                self.domain_analysis[domain]["methods"]["optimistic"] = \
                    self.domain_analysis[domain]["methods"].get("optimistic", 0) + 1
                return VerificationResult(email, True, corporate_reason, "optimistic")

        # 6. Default fallback - assume valid
        self.domain_analysis[domain]["valid"] += 1
        return VerificationResult(email, True, "Passed basic checks", "fallback")

    async def verify_email_with_semaphore(self, email: str):
        """Wrap verify_email with semaphore"""
        async with self.semaphore:
            return await self.verify_email(email)

    async def verify_batch(self, emails: List[str]) -> None:
        """Batch verification with progress tracking"""
        total_emails = len(emails)
        
        with tqdm(total=total_emails, desc="Verifying emails", unit="email") as pbar:
            tasks = [self.verify_email_with_semaphore(email) for email in emails]
            
            for future in asyncio.as_completed(tasks):
                try:
                    result = await future
                    if result.is_valid:
                        self.valid_emails.add(result.email)
                    else:
                        self.invalid_emails.add(result.email)
                    self.verification_results.append(result)
                except Exception as e:
                    # Handle unexpected errors
                    self.invalid_emails.add("error")
                    self.verification_results.append(
                        VerificationResult("error", False, f"Verification error: {str(e)}", "error")
                    )
                finally:
                    pbar.update(1)

    def load_emails_from_file(self, filename: str) -> List[str]:
        """Load emails from Excel file"""
        emails = set()
        
        try:
            workbook = openpyxl.load_workbook(filename, read_only=True)
            sheet = workbook.active
            
            for row in sheet.iter_rows(values_only=True):
                for cell_value in row:
                    if cell_value and isinstance(cell_value, str):
                        found_emails = re.findall(
                            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                            cell_value
                        )
                        for email in found_emails:
                            emails.add(email.strip().lower())
            
            workbook.close()
            
        except Exception as e:
            raise Exception(f"Error loading emails: {e}")
        
        print(f"Found {len(emails)} unique emails")
        return list(emails)

    def export_results(self, base_filename: str = 'email_verification_results'):
        """Export results with detailed analysis"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_filename = f"{base_filename}_{timestamp}"

        # Export valid emails
        with open(f"{base_filename}_valid.txt", 'w', encoding='utf-8') as f:
            for email in sorted(self.valid_emails):
                f.write(email + '\n')

        # Export invalid emails
        with open(f"{base_filename}_invalid.txt", 'w', encoding='utf-8') as f:
            for email in sorted(self.invalid_emails):
                if email != "error":  # Skip error placeholder
                    f.write(email + '\n')

        # Export detailed results
        with open(f"{base_filename}_detailed.csv", 'w', encoding='utf-8') as f:
            f.write("Email,Status,Reason,Method\n")
            for result in self.verification_results:
                if result.email != "error":  # Skip error placeholder
                    f.write(f'{result.email},{result.is_valid},"{result.reason}",{result.method}\n')

        # Export summary
        valid_count = len(self.valid_emails)
        invalid_count = len([e for e in self.invalid_emails if e != "error"])
        total_count = valid_count + invalid_count
        
        with open(f"{base_filename}_summary.txt", 'w', encoding='utf-8') as f:
            f.write("Email Verification Summary\n")
            f.write("=========================\n\n")
            f.write(f"Total emails processed: {total_count}\n")
            f.write(f"Valid emails: {valid_count}\n")
            f.write(f"Invalid emails: {invalid_count}\n")
            if total_count > 0:
                f.write(f"Success rate: {(valid_count/total_count*100):.1f}%\n\n")
            
            f.write("Verification Methods:\n")
            method_counts = {}
            for result in self.verification_results:
                if result.email != "error":
                    method_counts[result.method] = method_counts.get(result.method, 0) + 1
            
            for method, count in method_counts.items():
                f.write(f"  {method}: {count} emails\n")

        print(f"✅ Valid emails: {valid_count}")
        print(f"❌ Invalid emails: {invalid_count}")
        if total_count > 0:
            print(f"📊 Success rate: {(valid_count/total_count*100):.1f}%")
        print(f"💾 Results saved with prefix: {base_filename}")


def create_hunter_gui():
    """GUI for Hunter.io configuration"""
    root = tk.Tk()
    root.title("Hunter.io Email Verifier")
    root.geometry("500x350")
    
    # Main frame
    main_frame = ttk.Frame(root, padding="20")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    # Title
    title_label = ttk.Label(main_frame, text="Hunter.io Email Verification", 
                           font=("Arial", 14, "bold"))
    title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
    
    # API Key
    ttk.Label(main_frame, text="Hunter.io API Key:", 
             font=("Arial", 11)).grid(row=1, column=0, sticky="w", pady=5)
    
    api_key_var = tk.StringVar()
    api_key_entry = ttk.Entry(main_frame, textvariable=api_key_var, 
                             width=40, show="*", font=("Arial", 10))
    api_key_entry.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
    
    # API Key help
    api_help_text = "• Get your API key from hunter.io\n• Required for accurate email verification"
    api_help = ttk.Label(main_frame, text=api_help_text, font=("Arial", 9), 
                        foreground="gray", justify=tk.LEFT)
    api_help.grid(row=3, column=0, sticky="w", pady=(0, 20))
    
    # Modes
    mode_frame = ttk.LabelFrame(main_frame, text="Verification Modes", padding="10")
    mode_frame.grid(row=4, column=0, sticky="ew", pady=10)
    
    strict_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(mode_frame, text="Strict Mode (MX record checking)", 
                   variable=strict_var).pack(anchor="w", pady=2)
    
    optimistic_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(mode_frame, text="Optimistic Mode (corporate domains)", 
                   variable=optimistic_var).pack(anchor="w", pady=2)
    
    # Info
    info_text = """
    🔍 Verification Process:
    1. Hunter.io API verification (most accurate)
    2. MX record checking (if strict mode enabled)
    3. Corporate domain detection (if optimistic mode)
    4. Basic validation fallback
    """
    info_label = ttk.Label(main_frame, text=info_text, justify=tk.LEFT,
                          font=("Arial", 9), foreground="blue")
    info_label.grid(row=5, column=0, sticky="w", pady=10)
    
    # Button frame
    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=6, column=0, pady=20)
    
    def submit():
        if not api_key_var.get().strip():
            messagebox.showerror("Error", "Hunter.io API key is required")
            return
            
        root.api_key = api_key_var.get().strip()
        root.strict_mode = strict_var.get()
        root.optimistic_mode = optimistic_var.get()
        root.destroy()
    
    ttk.Button(button_frame, text="Start Verification", 
              command=submit, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    
    ttk.Button(button_frame, text="Cancel", 
              command=root.destroy).pack(side=tk.LEFT, padx=5)
    
    # Configure grid weights
    main_frame.columnconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    
    # Style for accent button
    style = ttk.Style()
    style.configure("Accent.TButton", foreground="white", background="#007acc")
    
    root.mainloop()
    
    return (
        getattr(root, 'api_key', None),
        getattr(root, 'strict_mode', False),
        getattr(root, 'optimistic_mode', True),
    )


async def main():
    """Main function"""
    try:
        api_key, strict_mode, optimistic_mode = create_hunter_gui()
        
        if not api_key:
            print("No API key provided. Exiting.")
            return

        # Create verifier
        verifier = HunterEmailVerifier(
            api_key=api_key,
            strict_mode=strict_mode,
            optimistic_mode=optimistic_mode,
        )

        # File selection
        root = tk.Tk()
        root.withdraw()
        
        input_file = filedialog.askopenfilename(
            title="Select Excel file with emails",
            filetypes=[("Excel files", "*.xlsx *.xls"), ("All files", "*.*")]
        )
        
        if not input_file:
            print("No file selected. Exiting.")
            return

        print("Loading emails...")
        emails = verifier.load_emails_from_file(input_file)
        
        if not emails:
            print("No valid emails found. Exiting.")
            return

        print(f"Starting verification of {len(emails)} emails using Hunter.io API...")
        start_time = time.time()
        
        await verifier.verify_batch(emails)
        
        end_time = time.time()
        
        base_filename = os.path.splitext(os.path.basename(input_file))[0]
        verifier.export_results(base_filename)

        print(f"⏱ Time taken: {end_time - start_time:.2f} seconds")
        print(f"✅ Verification complete")
        
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        print(f"Error: {e}")
    finally:
        if 'root' in locals():
            root.destroy()


if __name__ == "__main__":
    # Run the application
    asyncio.run(main())