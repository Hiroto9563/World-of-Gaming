"use strict;"
if (document.getElementById("worldofConsoles")) {
    document.getElementById("worldOfConsoles").innerHTML = "<h2 class='text-primary text-center'>World of Consoles</h2><p class='text-muted'>The first offical console was the Magnovox Odyssey. This console was of similar size to an old CRT monitor. Sonic wouldve had a blast with it but he was released until 19 years later. The consoles of the past were far larger than todays, much like how games you could play were very limited in comparision. Despite these limitations, early consoles set in motion a movement that would result in motion one of the largest industries in the world. Take a look at the consoles of the past as well as those of the present and gain a deeper apprication of the history and growth that the systems we play on have undergone. </p>";
    document.getElementById("worldOfGames").innerHTML = "<h2 class='text-primary text-center'>World of Games</h2><p class='text-muted'>The first ever video game was Tennis for two and was created years before the first console. The machine it was played on was of similar size to your car. What about the first game played on a console? That would be 12 different games, but the most widly known would probably be Pong, or Ping-Pong. Nowadays titles such as The Legend of Zelda Tears of the Kingdom or the recently released Super Mario Dreamland are common place and as a result we have lost our appriciation of the classics. Learn more about how far video games have come and what kind of changes occured over the course of their development. Sometimes the classics are better. </p>";
    document.getElementById("ourPicks").innerHTML = "<h2 class='text-primary text-center'>Our Picks!</h2><p class='text-muted'>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Deserunt quasi facilis sunt! Excepturi consequatur eos porro magnam nam dicta, mollitia unde illum at, accusantium delectus. Eos tempora saepe asperiores fugiat! Lorem ipsum dolor sit amet consectetur adipisicing elit. Deleniti ipsam dolorem architecto nam rerum labore explicabo mollitia quis cumque ratione, minus ipsa, culpa provident laboriosam impedit distinctio fuga sed earum! Lorem ipsum, dolor sit amet consectetur adipisicing elit. Incidunt atque error, nemo temporibus voluptas officiis quam inventore! Hic cumque, recusandae eos harum soluta amet qui laboriosam eveniet fugiat optio at.</p>";
    document.getElementById("whatsNew").innerHTML = "<h2 class='text-primary text-center'>What's New?</h2><p class='text-muted'>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Deserunt quasi facilis sunt! Excepturi consequatur eos porro magnam nam dicta, mollitia unde illum at, accusantium delectus. Eos tempora saepe asperiores fugiat! Lorem ipsum dolor sit amet consectetur adipisicing elit. Deleniti ipsam dolorem architecto nam rerum labore explicabo mollitia quis cumque ratione, minus ipsa, culpa provident laboriosam impedit distinctio fuga sed earum! Lorem ipsum, dolor sit amet consectetur adipisicing elit. Incidunt atque error, nemo temporibus voluptas officiis quam inventore! Hic cumque, recusandae eos harum soluta amet qui laboriosam eveniet fugiat optio at.</p>";
}

Consoles = [
    ["1972 - Magnavox Odyssey ","The Magnavox Odyssey was the first-ever home console. It was created by Sanders Associates and sold 350,000 units by the time it was discontinued in 1975. ","https://upload.wikimedia.org/wikipedia/commons/thumb/9/99/Magnavox-Odyssey-Console-Set.jpg/330px-Magnavox-Odyssey-Console-Set.jpg"],
    ["1974 - Fairchild Video Entertainment System","Also known as the Fairchild Channel F, it was created by Alpex Computer Corp. and was the first console to use a game cartridge. It sold for $170 ($910 today).","https://upload.wikimedia.org/wikipedia/commons/thumb/3/34/Fairchild-Channel-F.jpg/330px-Fairchild-Channel-F.jpg"],
    ["1977 - Atari 2600","The Atari 2600 was the first home console to implement the game cartridge. Around 30 million units sold for around $125 each, ($390 today).","https://upload.wikimedia.org/wikipedia/commons/thumb/0/02/Atari-2600-Wood-4Sw-Set.png/330px-Atari-2600-Wood-4Sw-Set.png"],
    ["1983 - Nintendo Entertainment System","This system was called an entertainment system instead of a video game console due to the stigma behind the name due to the 1983 video game crash.","https://upload.wikimedia.org/wikipedia/commons/thumb/b/b2/NES-Console-Set.png/330px-NES-Console-Set.png"],
    ["1983 - Sega SG - 1000","This console was created at the same time as the NES, due to the recommendation of Hayao Nakayama who was the president of the SEGA Japanese branch. ","https://upload.wikimedia.org/wikipedia/commons/thumb/7/7b/Sega-SG-1000-Console-Set.jpg/330px-Sega-SG-1000-Console-Set.jpg"],
    ["1987 - Sega Genesis","Despite having an 8-bit processor, it had a 16-bit graphics processor which made it comparable to other consoles released around that time. ","https://upload.wikimedia.org/wikipedia/commons/thumb/a/a1/Sega-Mega-Drive-JP-Mk1-Console-Set.jpg/375px-Sega-Mega-Drive-JP-Mk1-Console-Set.jpg"],
    ["1989 - Game Boy","The handheld featured an LCD screen and came with Tetris as a package, making it a best seller. This device also kickstarted the Kirby franchise.","https://upload.wikimedia.org/wikipedia/commons/thumb/f/f4/Game-Boy-FL.jpg/330px-Game-Boy-FL.jpg"],
    ["1989 - Atari Lynx","This device was the first handheld console with a color display and featured an 8-bit CPU. It was considered superior to the Game Boy. ","https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/Atari-Lynx-I-Handheld.jpg/330px-Atari-Lynx-I-Handheld.jpg"],
    ["1990 - Super Nintendo Entertainment System","The Sega Genesis and the Super Nintendo entertainment systems had a rivalry on the market that was dubbed the console wars. ","https://upload.wikimedia.org/wikipedia/commons/thumb/3/31/SNES-Mod1-Console-Set.jpg/375px-SNES-Mod1-Console-Set.jpg"],
    ["1993 - Atari Jaguar","The console sported two 32-bit processors dubbed “Tom and Jerry” and was advertised as the first 64-bit game system.","https://upload.wikimedia.org/wikipedia/commons/thumb/9/90/Atari-Jaguar-Console-Set.png/330px-Atari-Jaguar-Console-Set.png"],
    ["1994 - Sony Playstation","The playstation is the result of a failed venture between sony and Nintendo to add an optical peripheral to the SNES. ","https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/PlayStation-SCPH-1000-with-Controller.jpg/375px-PlayStation-SCPH-1000-with-Controller.jpg"],
    ["1995 - Sega Saturn","This console gained popularity due to Sega's recent release of 3D graphics and the inclusion of game discs.","https://upload.wikimedia.org/wikipedia/commons/thumb/2/20/Sega-Saturn-Console-Set-Mk1.png/375px-Sega-Saturn-Console-Set-Mk1.png"],
    ["1995 - Virtual Boy","This console was the first attempt at virtual reality, its design could have been more appealing and appealing which led to Nintendo refocusing on the Game Boy.","https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Virtual-Boy-Set.jpg/300px-Virtual-Boy-Set.jpg"],
    ["1996 - Nintendo 64","This console was the last to use game cartridges but had 3D graphics thanks to its 64-bit processor. Its launch date was delayed by a year to finish developing its launch games Super Mario 64 and Pilotwings 64. ","https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/N64-Console-Set.jpg/330px-N64-Console-Set.jpg"],
    ["1998 - Dreamcast","This console was the first home console to feature a modem. This allowed users to access online play. ","https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/Dreamcast-Console-Set.png/330px-Dreamcast-Console-Set.png"],
    ["2000 - PlayStation 2","The PlayStation 2 is the best-selling console of all time with 155 million units sold.","https://upload.wikimedia.org/wikipedia/commons/thumb/1/1c/PS2-Versions.jpg/330px-PS2-Versions.jpg"],
    ["2001 - Game Cube","The Game Cube was the first Nintendo console to use discs instead of cartridges. ","https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/GameCube-Set.jpg/330px-GameCube-Set.jpg"],
    ["2001 - Xbox","Created by Microsoft, it was the second-ever console created by an American company.","https://upload.wikimedia.org/wikipedia/commons/thumb/a/a7/Xbox-Console-wDuke-L.jpg/375px-Xbox-Console-wDuke-L.jpg"],
    ["2001 - Game Boy Advance","The Gameboy Advance was built with a 32-bit CPU and was created as the last Gameboy console.","https://upload.wikimedia.org/wikipedia/commons/thumb/7/7d/Nintendo-Game-Boy-Advance-Purple-FL.jpg/450px-Nintendo-Game-Boy-Advance-Purple-FL.jpg"],
    ["2003 - N-Gage","The N-gage was created by Nokia in an attempt to combine a cellphone and a game system. ","https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Nokia-NGage-LL.jpg/390px-Nokia-NGage-LL.jpg"],
    ["2004 - Nintendo DS","The Nintendo DS was the first handheld console with the capability to connect multiple systems over wifi.","https://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Nintendo-DS-Fat-Blue.jpg/330px-Nintendo-DS-Fat-Blue.jpg"],
    ["2004 - PlayStation Portable","The PlayStation Portable was the most powerful handheld device of its time and was also the only ever handheld console to use disks instead of cartridges. ","https://upload.wikimedia.org/wikipedia/commons/thumb/4/46/Psp-1000.jpg/330px-Psp-1000.jpg"],
    ["2005 - Xbox 360","The Xbox 360 was the 9th best-selling console in history. It would have sold more units had it not been for supply issues during the first year of its release.","https://upload.wikimedia.org/wikipedia/commons/thumb/7/76/Xbox-360S-Console-Set.jpg/128px-Xbox-360S-Console-Set.jpg"],
    ["2006 - Wii","The Wii was created to focus on appealing to a broader audience with casual gameplay instead of competing with the Sony and Sega. ","https://upload.wikimedia.org/wikipedia/commons/thumb/f/f3/Wii-Console.png/330px-Wii-Console.png"],
    ["2011 - Nintendo 3DS","The Nintendo 3DS started at a price of $249.99 but they dropped the price to $169.99 after poor sales after launch. ","https://upload.wikimedia.org/wikipedia/commons/thumb/f/f0/Nintendo-3DS-AquaOpen.jpg/330px-Nintendo-3DS-AquaOpen.jpg"],
    ["2012 - Wii U","The Wii U was the first Nintendo console to sport HD graphics. It was created to compete with the Xbox 360 and Playstation 3.","https://upload.wikimedia.org/wikipedia/commons/thumb/4/4a/Wii_U_Console_and_Gamepad.png/330px-Wii_U_Console_and_Gamepad.png"],
    ["2013 - Nintendo 2DS","The Nintendo 2DS was created for children 7 and under due to concerns of eye injuries cause from the 3D functions of the 3DS.","https://upload.wikimedia.org/wikipedia/commons/thumb/1/14/Nintendo-2DS-angle.jpg/330px-Nintendo-2DS-angle.jpg"],
    ["2013 - Xbox 1","The Xbox 1 faced criticism for its poor graphical quality in comparison to the Playstation 4. ","https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Microsoft-Xbox-One-Console-Set-wKinect.jpg/450px-Microsoft-Xbox-One-Console-Set-wKinect.jpg"],
    ["2013 - Playstation 4","The Playstation 4 was created to emphasize social interaction and was subsequently praised for acknowledging the want of the user base.  ","https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/PS4-Console-wDS4.png/330px-PS4-Console-wDS4.png"],
    ["2017 - Nintendo Switch","The Nintendo Switch is classified as a hybrid console due to its ability to be played as a table or be docked and used as a console. ","https://upload.wikimedia.org/wikipedia/commons/thumb/8/88/Nintendo-Switch-wJoyCons-BlRd-Standing-FL.jpg/450px-Nintendo-Switch-wJoyCons-BlRd-Standing-FL.jpg"],
    ["2020 - Xbox Series X","The Xbox Series X and S were originally referred to as codename “Scarlette” as a whole with each individually being called “Anoconda” and “Lockhart”. ","https://upload.wikimedia.org/wikipedia/commons/thumb/1/12/Xbox_Series_X_2.jpg/167px-Xbox_Series_X_2.jpg"],
    ["2020 - Playstation 5","The Playstation 5 is notorious for being hard to obtain due to the global chip shortage in 2020-2023. This problem was compounded by the prevailance of scalping that took place.","https://upload.wikimedia.org/wikipedia/commons/thumb/7/77/Black_and_white_Playstation_5_base_edition_with_controller.png/330px-Black_and_white_Playstation_5_base_edition_with_controller.png"]
];

var consolesHTML = "";
if (document.getElementById("consoleHTML")) {
    for(let i = 0; i < Consoles.length; i++){
        consolesHTML += "<div class='col-12 col-sm-12 col-md-6 col-lg-4'>\
                            <div class='border border-3 rounded-4 border-primary p-3 m-3 bg-light'>\
                                <h2 class='text-danger text-center'>";
        for (let j = 0; j < Consoles[i].length; j++) {
            if (j == 0){
                consolesHTML += Consoles[i][j] + "</h2> <p class='text-muted'>";
            }
            if (j == 1){
                consolesHTML += Consoles[i][j] + "</p> <img src='";
            }
            if (j == 2) {
                consolesHTML += Consoles[i][j] + "' alt='Console' width='300px' height='300px'></img>"
            }
        }
        consolesHTML += "</div> </div>"
    }

    document.getElementById("consoleHTML").innerHTML = consolesHTML;
}
