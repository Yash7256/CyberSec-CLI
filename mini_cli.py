#!/usr/bin/env python3
"""Minimal CLI test without any external dependencies."""

def main():
    print("\n=== Minimal Cybersec CLI Test ===")
    print("Type something and press Enter. Type 'exit' to quit.\n")
    
    while True:
        try:
            # Simple input without any fancy libraries
            user_input = input("mini-cli> ")
            
            if user_input.lower() in ('exit', 'quit'):
                print("Exiting...")
                break
                
            print(f"You typed: {user_input}")
            
        except (KeyboardInterrupt, EOFError):
            print("\nUse 'exit' or 'quit' to exit")
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
