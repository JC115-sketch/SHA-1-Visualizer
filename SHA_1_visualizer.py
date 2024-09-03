import SHA_1

def sha1_visualizer(message):
    print("Starting SHA-1 visualization for message:", message)

    # Step 1: Padding
    proceed = input("Press enter to proceed to padding step, or 'q' to quit: ")
    if proceed.lower() == 'q':
        return
    
    padded_message = SHA_1.sha1_padding(message.encode('utf-8'))
    print("\nStep 1: Padding input message so that it is of length 448 mod 512 bits, "
          "remaining 64 represent original message's length")
    print("Padded message:", padded_message.hex())
    
    # Step 2: Block Creation
    proceed = input("\nPress Enter to proceed to block splitting step, or 'q' to quit: ")
    if proceed.lower() == 'q':
        return
    
    blocks = SHA_1.sha1_blocks(padded_message)
    print("\nStep 2: Splitting the message into blocks")
    print("Number of blocks:", len(blocks))

    # Step 3: Initialize Hash Values
    print("\nGenerating initial hash values")
    h0, h1, h2, h3, h4 = SHA_1.sha1_initialize_hash_values()

    # Step 4: Process Each Block
    for i, block in enumerate(blocks):
        print(f"\nProcessing Block {i + 1}:")
        print("Block content:", block.hex())

        # Step 4a: Calculate Message Schedule
        print("\nCalculating message schedule:")
        w = SHA_1.sha1_message_schedule(block)

        # Step 4b: Compression Function
        print("\nStarting compression")
        h0, h1, h2, h3, h4 = SHA_1.sha1_compress(h0, h1, h2, h3, h4, block)

    # Step 5: Final Hash Calculation
    proceed = input("\nPress Enter to calculate the final hash, or 'q' to quit: ")
    if proceed.lower() == 'q':
        return

    final_hash = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}"
    print("\nFinal hash:", final_hash)

    
# Example usage:
if __name__ == "__main__":
    message = input("Enter the message to hash: ")
    sha1_visualizer(message)
    

