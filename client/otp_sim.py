import pyotp
import time
import sys

def main():
    """
    Simulates a phone-based TOTP (Time-Based One-Time Password) generator.
    
    Flow:
      1) The user is prompted for a TOTP secret. 
         (In a real scenario, you'd retrieve this secret when registering 
         or from the server logs in your project.)
      2) It creates a pyotp.TOTP instance from that secret.
      3) The program repeatedly shows the current OTP and how many seconds 
         remain until it expires (based on the interval, usually 30 seconds).
      4) Press Ctrl+C to exit gracefully.
    """
    print("[INFO] This program simulates a phone-based TOTP generator.")
    print("[INFO] You can get the TOTP secret from your server logs or DB after you register an account.")
    print("[INFO] Press Ctrl+C to stop.\n")

    # Ask for the TOTP secret (a Base32 string)
    secret = input("Enter your TOTP secret: ").strip()
    if not secret:
        print("[ERROR] No secret provided. Exiting.")
        sys.exit(1)

    # Create a pyotp.TOTP object from the secret
    try:
        totp = pyotp.TOTP(secret)
    except Exception as e:
        print(f"[ERROR] Failed to create TOTP with secret: {e}")
        sys.exit(1)

    print("[INFO] TOTP simulator started successfully!\n")

    # By default, pyotp.TOTP uses a 30-second interval, but it can be different
    interval = totp.interval

    while True:
        # current_otp is the 6-digit code at the present time
        current_otp = totp.now()
        # time_left calculates how many seconds remain until the next code
        time_left = interval - (int(time.time()) % interval)

        # Use "\r" to overwrite the same line; flush the output to update in place
        sys.stdout.write(f"\rCurrent OTP = {current_otp} | Expires in {time_left:2d} sec ")
        sys.stdout.flush()

        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] TOTP simulator stopped by user. Goodbye!")
