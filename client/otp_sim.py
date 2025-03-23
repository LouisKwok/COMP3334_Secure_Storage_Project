import pyotp
import time
import sys

def main():
    print("[INFO] This program simulates a phone-based TOTP generator.")
    print("[INFO] You can get the TOTP secret from your server logs or DB after you register an account.")
    print("[INFO] Press Ctrl+C to stop.\n")

    secret = input("Enter your TOTP secret: ").strip()
    if not secret:
        print("[ERROR] No secret provided. Exiting.")
        sys.exit(1)

    try:
        totp = pyotp.TOTP(secret)
    except Exception as e:
        print(f"[ERROR] Failed to create TOTP with secret: {e}")
        sys.exit(1)

    print("[INFO] TOTP simulator started successfully!\n")

    interval = totp.interval

    while True:
        current_otp = totp.now()      
        time_left = interval - (int(time.time()) % interval)  

        sys.stdout.write(f"\rCurrent OTP = {current_otp} | Expires in {time_left:2d} sec ")
        sys.stdout.flush()

        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] TOTP simulator stopped by user. Goodbye!")
