#!/usr/bin/env python3

# Dustin Marchak
# CSCI 5180 - Midterm Lab
# NMmain.py - Main menu to run each lab script.

# imports
import NMtcpdump, NMdhcpserver, NMsnmp, NMgithub # import modules
import asyncio # required to run async NMsnmp main function



def main():
    while True:
        # display the menu
        print("\n===== CSCI 5180 Midterm Lab =====")
        print("1. NMtcpdump   - Parse pcap and discover MAC addresses")
        print("2. NMdhcpserver - Configure DHCP pools on R5")
        print("3. NMsnmp      - SNMP queries and CPU monitoring")
        print("4. NMgithub    - Push files to GitHub")
        print("5. Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":
            NMtcpdump.main()
        elif choice == "2":
            NMdhcpserver.main()
        elif choice == "3":
            asyncio.run(NMsnmp.main())
        elif choice == "4":
            NMgithub.main()
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid selection. Please enter 1-5.")


# namespace check
if __name__ == "__main__":
    main()
