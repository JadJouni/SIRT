import re
import requests
import hashlib
import argparse


def main():
    parser = argparse.ArgumentParser(description="SIRT - Security Intelligence & Reconnaissance Tool")
    
    parser.add_argument('-u', '--url', type=str, help='URL to audit web headers')
    parser.add_argument('-p', '--password', type=str, help='Password to check for breaches')
    parser.add_argument('-o', '--output', type=str, help='Output file to save results')
                        
    args = parser.parse_args()
    
    output_lines = []
    def print_and_collect(text=""):
        """Helper function to both print and collect output"""
        print(text)
        output_lines.append(text)
    
    
    
    
    
    if not args.url and not args.output and not args.password:
        
        parser.print_help()
        return

    if args.url:
         print_and_collect("\n" + "="*60)
         print_and_collect("SECURITY HEADER AUDIT")
         print_and_collect("="*60)
        
        
         if not validate_input(args.url, "url"):
            print_and_collect(f"❌ Error: Invalid URL format: {args.url}")
            print_and_collect("   URL must start with http:// or https://")
            return
        
         print_and_collect(f"Target: {args.url}\n")
        
         try:
          
             results = audit_web_headers(args.url)
            
            
             print_and_collect("Security Headers Status:")
             print_and_collect("-" * 60)
            
             for header, is_present in results.items():
                if is_present:
                    status = "✓ PRESENT"
                    symbol = "[+]"
                else:
                    status = "✗ MISSING"
                    symbol = "[-]"
                
                print_and_collect(f"{symbol} {header:40} {status}")
            
            # Summary
             present_count = sum(results.values())
             total_count = len(results)
             missing_count = total_count - present_count
            
             print_and_collect("-" * 60)
             print_and_collect(f"Summary: {present_count}/{total_count} headers present, {missing_count} missing")
            
             if missing_count > 0:
                print_and_collect("⚠️  Warning: Missing security headers may leave the site vulnerable")
             else:
                print_and_collect("✓ All recommended security headers are present!")
            
         except Exception as e:
            print_and_collect(f"❌ Error auditing URL: {e}")

    if args.password:
         print_and_collect("\n" + "="*60)
         print_and_collect("PASSWORD BREACH CHECK")
         print_and_collect("="*60)
         print_and_collect("Checking password against known data breaches...\n")
        
         try:
            # Check the password
            breach_count=check_password_breach(args.password)
            
            # Display results
            if breach_count > 0:
                print_and_collect(f"⚠️ WARNING: Password found in {breach_count:,} data breaches!")
                print_and_collect("   The password is compromised and should NOT be used.")
                print_and_collect("   Recommendation: Use a unique,strong password instead.")
            else:
                print_and_collect("✓ This password was not found in known breaches.")
               
        
         except Exception as e:
            print_and_collect(f"❌ Error checking password: {e}")
    
    print_and_collect("\n" + "="*60)
    print_and_collect("Scan complete!")
    print_and_collect("="*60 + "\n")
    
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            print (f"\nReport saved to: {args.output}")
                   
        except Exception as e:
             print(f"\nError saving report to file: {e}")
    
    
    


       
def validate_input(target, input_type):
    
    #feature not implemented
    if input_type== "email":
        pattern= r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return bool(re.match(pattern, target))
        
        
    if input_type== "url" :
        pattern=r"https?://[\w\-\.]+(?:/[\w\-\.\\=\?\&\%\+\,\!]*)*"  #r'^(https?://)?(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/[\w./?%&=-]*)?$'
        return bool(re.match(pattern, target))
    
    else:
        raise ValueError("Unsupported input type")

def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    prefix =sha1_hash[:5].upper()
    suffix =sha1_hash[5:].upper()
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    #if request was not sccfl
    if response.status_code != 200:
        raise Exception("Error fetching data from API")
    
    hashes = response.text.splitlines()
    
    for line in hashes:
        hash_suffix, count = line.split(':')
        
        if hash_suffix == suffix:
            return int(count)   
    
    return 0
    
    
def audit_web_headers(url):
   
    try:
       
        response = requests.head(url, allow_redirects=True)
        
      
        if response.status_code >= 400:
            raise Exception(f"HTTP Error: {response.status_code}")
        
        
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        
        results = {}
        
        
        for header in security_headers:
            
            results[header] = header in response.headers
        
        return results
    
    except requests.RequestException as e:
        raise Exception(f"Error fetching URL: {e}")
    





















if __name__ == "__main__":
    main()

    
            

    
    
