from enigma.machine import EnigmaMachine

rotor = ["I II III", 	"I II IV", 	"I II V",  	"I III II",
         "I III IV", 	"I III V", 	"I IV II", 	"I IV III",
         "I IV V", 	"I V II", 	"I V III", 	"I V IV",
         "II I III", 	"II I IV", 	"II I V", 	"II III I",
         "II III IV", 	"II III V", 	"II IV I", 	"II IV III",
         "II IV V", 	"II V I", 	"II V III", 	"II V IV",
         "III I II",	"III I IV",	"III I V",	"III II I",
         "III II IV", 	"III II V",	"III IV I",	"III IV II",
         "III IV V", 	"IV I II",	"IV I III",	"IV I V",
         "IV II I",	"IV II III",	"IV I V",	"IV II I",
         "IV II III",	"IV II V",	"IV III I",	"IV III II",
         "IV III V",	"IV V I",	"IV V II",	"IV V III",
         "V I II",	"V I III",	"V I IV",	"V II I",
         "V II III", 	"V II IV",	"V III I",	"V III II",
         "V III IV",	"V IV I",	"V IV II",	"V IV III"	]  # all possible rotor picking


def find_rotor_start(rotor_choice, ciphertext, cribtext):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # All possible rotor alphabet

    for a in range(1, 27):  # search for rotor 1 ring setting
        for b in range(1, 27):  # search for rotor 2 ring setting
            for c in range(1, 27):  # search for rotor 3 ring setting
                for i in range(len(alphabet)):  # search for rotor 1 start position
                    for j in range(len(alphabet)):  # search for rotor 2 start position
                        # search for rotor 3 start position
                        for k in range(len(alphabet)):
                            # generate a possible rotor start position
                            start_pos = alphabet[i] + alphabet[j] + alphabet[k]
                            # generate a possible ring setting
                            ring_settings = [a, b, c]

                            print(
                                f"Brute-forcing... start_pos: {start_pos} ring_settings: {ring_settings}")

                            machine = EnigmaMachine.from_key_sheet(
                                rotors=rotor_choice,
                                reflector='B',
                                ring_settings=ring_settings,
                                plugboard_settings='UX JC PB MK TA RD SG QO LV FI')  # cheating becuase i known the plugboard settings [but you can analys from crib text]

                            # set machine initial starting position and attempt decrypt
                            machine.set_display(start_pos)
                            plaintext = machine.process_text(ciphertext)

                            # check if decrypt is the same as the crib text
                            if plaintext[:len(cribtext)] == cribtext:
                                # print( start_pos, plaintext, cribtext )
                                return(rotor_choice, start_pos, ring_settings, plaintext)

    return(rotor_choice, "null", "null", "null")


if __name__ == '__main__':
    # extract the cipher and crib texts
    ciphertext = input("Enter ciphertext: ")
    cribtext = input("Enter cribtext: ")

    print(
        f"Brute force crypt attack on Enigma message {ciphertext} using crib {cribtext}")

    # try all rotor settings
    for rotor_setting in rotor:
        print(("Trying rotors %s..." % (rotor_setting)))
        rotor_choice, start_pos, ring_settings, plaintext = find_rotor_start(
            rotor_setting, ciphertext, cribtext)
        if (start_pos != "null" and ring_settings != "null"):
            print(
                f"Machine setting found: rotors {rotor_choice}, message key was {start_pos}, ring settings was {ring_settings} using crib {cribtext}")
            print(f"Plaintext: {plaintext}")
            exit(0)
