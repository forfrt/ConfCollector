--[[
Copyright: 2015-2016, qingteng 
File name: jboss_check.lua
Description: jboss数据采集
Author: fengruitao
Version: 1.0
Date: 2016.6.8

Input:
{   
    "args":
    {
        "uuid":"",
        "args":[{"name":Type, "value":Value}]
    }
}

Post:
{
    "stream":{
        "args":{
            "uuid":""
        },
        "result":""
    }
}

Output:
{
    "ret_code":0
    "ret_msg":""
}

--]]
local begin_time = os.time()
agent.load "rex_pcre"
local rex=rex_pcre
local socket=agent.require "socket"
local common = agent.require "agent.platform.linux.common"
local begin_time=os.time()
local execute_shell=common.execute_shell
local execute_shell_l=common.execute_shell_l
local split=common.split
local get_str_md5=agent.get_str_md5
if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"jboss_check","value":"1"}]}}]]
end
local json_tb = cjson.decode(json_str)
local Debug=false

function get_weak_pwd()
    local pwd_list = {"admin","123456","12345","123456789","password","iloveyou","princess","12345678","1234567","abc123","nicole","daniel","monkey","babygirl","qwerty","lovely","654321","michael","jessica","111111","ashley","000000","iloveu","michelle","tigger","sunshine","chocolate","password1","soccer","anthony","friends","purple","angel","butterfly","jordan","fuckyou","123123","justin","liverpool","football","loveme","secret","andrea","jennifer","joshua","carlos","superman","bubbles","hannah","1234567890","amanda","andrew","loveyou","pretty","basketball","angels","flower","tweety","hello","playboy","charlie","elizabeth","samantha","hottie","chelsea","tinkerbell","shadow","barbie","666666","jasmine","lovers","brandon","teamo","matthew","melissa","eminem","robert","danielle","forever","dragon","computer","whatever","family","jonathan","cookie","summer","987654321","naruto","vanessa","sweety","joseph","spongebob","junior","taylor","softball","mickey","yellow","lauren","daniela","princesa","william","alexandra","thomas","jesus","alexis","miguel","estrella","patrick","angela","mylove","poohbear","beautiful","iloveme","sakura","adrian","121212","destiny","alexander","christian","america","monica","dancer","112233","sayang","richard","diamond","orange","555555","princess1","carolina","steven","louise","rangers","snoopy","hunter","999999","killer","nathan","789456","11111","buster","shorty","gabriel","cherry","george","cheese","sandra","alejandro","rachel","brittany","ginger","patricia","alejandra","7777777","159753","pokemon","pepper","arsenal","maggie","peanut","baseball","dolphin","heather","david","tequiero","chicken","blink182","antonio","222222","victoria","sweetie","rainbow","stephanie","987654","beauty","honey","00000","fernando","cristina","corazon","kisses","manuel","angel1","martin","heaven","november","55555","rebelde","greenday","123321","ricardo","batman","babygurl","madison","123abc","mother","alyssa","morgan","asshole","december","bailey","mahalkita","september","mariposa","maria","sophie","jeremy","gemini","pamela","gabriela","shannon","iloveyou2","kimberly","jessie","pictures","austin","claudia","hellokitty","booboo","master","harley","angelica","babygirl1","victor","horses","courtney","tiffany","mahalko","eduardo","kissme","mariana","peaches","andres","banana","precious","chris","october","ronaldo","inuyasha","veronica","iloveyou1","888888","freedom","james","prince","oliver","jesus1","zxcvbnm","adriana","samsung","cutie","friend","crystal","edward","scooby","celtic","rebecca","jackie","carmen","kenneth","diana","angelo","johnny","456789","sebastian","school","spiderman","karina","mustang","christopher","slipknot","august","orlando","0123456789","samuel","monkey1","adidas","cameron","barcelona","casper","bitch","kitten","internet","50cent","kevin","cutiepie","brenda","bonita","babyboy","maganda","karen","natalie","fuckoff","123654","isabel","sarah","silver","cuteako","javier","jasper","789456123","777777","tigers","marvin","rockstar","bowwow","nicholas","chester","laura","portugal","smokey","denise","asdfgh","flowers","january","tintin","alicia","volleyball","101010","bianca","garfield","cristian","dennis","cassie","696969","chrisbrown","sweet","francis","midnight","strawberry","panget","love123","lollipop","benfica","aaaaaa","olivia","welcome","apples","charles","cancer","qwertyuiop","ihateyou","vincent","mercedes","nirvana","jordan23","letmein","camila","monique","superstar","harrypotter","fucker","scorpio","pookie","icecream","christine","benjamin","mexico","abigail","charmed","131313","lorena","lovelove","abcdef","katherine","andreea","333333","rafael","brianna","love","aaliyah","brooke","johncena","dakota","gangsta","jackson","michael1","hiphop","travis","sabrina","metallica","julian","stephen","jeffrey","sergio","mybaby","babyblue","fluffy","badboy","simple","smiley","catherine","dolphins","melanie","blondie","westlife","newyork","fernanda","sasuke","88888888","muffin","piglet","roberto","teresa","steaua","jason","minnie","ronald","asdfghjkl","popcorn","raymond","slideshow","kitty","santiago","scooter","5201314","dexter","jerome","jayson","246810","ladybug","gandako","cookies","gatita","leslie","babyko","lalala","christ","alberto","232323","jenny","sweetheart","chivas","leonardo","nicole1","rockon","marcus","valeria","anthony1","babydoll","jayjay","brooklyn","cocacola","12345678910","sexygirl","bitch1","liliana","happy","chris1","amores","eeyore","natasha","skittles","fatima","252525","single","lover","london","winnie","159357","miamor","123456a","colombia","manutd","lakers","hahaha","britney","albert","katrina","teddybear","linda","elephant","grace","christina","marie","stupid","hockey","0123456","pasaway","snickers","mahal","turtle","tatiana","charlotte","smile","147258369","cantik","qazwsx","teiubesc","genesis","shelby","natalia","spider","francisco","147258","xavier","kelsey","amorcito","angelito","claire","brandy","manchester","paola","fuckyou1","mommy1","marina","147852","bandit","phoenix","rabbit","amigos","444444","garcia","bonnie","linkinpark","marlon","sharon","guitar","dallas","starwars","disney","monster","frankie","diego","red123","pimpin","pumpkin","iverson","54321","andrei","england","soccer1","sparky","fashion","justine","allison","emily","102030","lucky1","456123","wilson","potter","danny","matrix","miranda","bestfriend","number1","canada","people","thunder","hermosa","barney","player","savannah","camille","sporting","katie","nelson","212121","yankees","scotland","timothy","hearts","iloveu2","truelove","hottie1","jasmin","smiles","bubble","onelove","jayden","florida","ilovehim","parola","ganda","brandon1","jackass","shakira","motorola","tennis","sweets","estrellita","westside","nikki","evelyn","biteme","monkeys","maryjane","lucky","trinity","loverboy","ronnie","love12","elijah","joanna","emmanuel","familia","broken","compaq","1234","omarion","hello1","999999999","mamita","rodrigo","justin1","jamaica","california","isabella","shopping","fuckyou2","gracie","nothing","kathleen","cupcake","mauricio","sammy","abcdefg","bradley","amigas","mariah","loser","connor","preciosa","ferrari","snowball","elaine","robbie","hector","flores","jorge","trustno1","darling","candy","martinez","sunflower","millie","jamie","melody","blessed","cheche","dominic","joanne","valentina","swimming","pebbles","tyler","friendster","santos","taurus","dreams","a123456","aaron","gloria","loving","gangster","sweetpea","kitkat","sunshine1","google","jessica1","cheyenne","dustin","violet","apple","sydney","darren","megan","darkangel","kelly","cynthia","zachary","froggy","charlie1","sophia","skater","123qwe","raiders","purple1","bettyboop","darkness","oscar","iubire","money","chacha","jordan1","010203","inlove","batista","bestfriends","marian","gerald","carebear","green","daddy1","pogiako","karla","billabong","sexyme","willow","cooper","pinky","daddysgirl","ashley1","bambam","tigger1","amber","fuckme","erika","nenita","dreamer","bella","gatito","butter","123789","buttercup","glitter","passion","lokita","sister","maldita","nichole","lindsey","sierra","lindsay","anderson","booger","miller","caroline","eagles","loveya","marissa","lovebug","nicolas","cecilia","zacefron","tokiohotel","lollypop","bubblegum","kristine","mario","puppies","mememe","carter","chubby","scorpion","ariana","sammie","11111111","stella","raquel","kristen","qwerty1","lonely","stacey","baller","chance","hotstuff","angelina","roxana","james1","susana","sexybitch","rocker","williams","012345","babylove","rocky","sweet16","freddy","lolita","remember","football1","catdog","kayla","playgirl","loveme1","marcos","zxcvbn","yamaha","gustavo","bhebhe","PASSWORD","hotdog","202020","daddy","151515","milagros","caitlin","vampire","lovely1","ireland","skyline","matthew1","xxxxxx","beyonce","lilmama","georgia","martha","gerard","armando","undertaker","margarita","bryan","kittycat","tristan","lizzie","dance","loves","password2","money1","amistad","tamara","boomer","simpsons","justme","capricorn","maddie","andrew1","amelia","delfin","legolas","sheila","141414","harvey","cheerleader","chiquita","gateway","cowboys","janine","penguin","enrique","patches","scoobydoo","genius","badgirl","israel","carlitos","happy1","dancing","cuteme","lester","angeles","peewee","walter","jesuschrist","awesome","thebest","deedee","lucky7","chichi","buddy1","angie","00000000","ashton","winter","michelle1","hardcore","tinker","myself","janice","paloma","tazmania","regina","cinderella","molly","miriam","poopoo","animal","april","ilovejesus","david1","murphy","please","felipe","spencer","tekiero","princesita","jesucristo","pussycat","johnson","lipgloss","melvin","rosita","jazmin","celeste","mierda","scarface","pangit","silvia","arturo","741852963","mylife","trixie","gorgeous","hernandez","chicago","panthers","daisy","yourmom","ilovegod","xbox360","babyboo","kristina","crazy","hawaii","honeyko","valerie","nikita","sparkle","debbie","loveu","tucker","098765","hollywood","wesley","lupita","alfredo","hailey","musica","abcd1234","sexymama","lawrence","242424","jeremiah","hayden","bullshit","marley","chloe","qwert","barbara","1q2w3e4r","micheal","lolipop","panther","jimmy","trouble","united","sheena","coffee","87654321","0987654321","diamonds","pineapple","isaiah","brian","blonde","christmas","bubbles1","sandy","jasmine1","pantera","marisol","cesar","twilight","shadow1","butterfly1","bananas","741852","whitney","mhine","julius","pauline","madalina","birthday","anamaria","drpepper","beatriz","eugene","bobby","donald","desiree","hannah1","sweetness","february","moomoo","twinkle","friendship","leanne","simone","shelly","anita","lover1","marie1","perfect","beckham","cookie1","cowboy","calvin","123123123","imissyou","samson","catalina","damian","ashlee","autumn","buddy","bebita","joshua1","147852369","andre","iloveyou!","titanic","daniel1","pollito","nursing","serenity","mommy","babyface","torres","bitches","dinamo","paradise","reggie","bulldogs","852456","animals","willie","juliana","alison","passw0rd","sexylady","robert1","cassandra","14344","mendoza","blossom","mariel","element","bethany","1111111","1q2w3e","creative","harold","bulldog","mitchell","diesel","marshall","amanda1","marcela","gerardo","maverick","peterpan","tanner","tyrone","cutie1","kucing","chanel","simpleplan","paulina","ILOVEYOU","fabian","pisces","always","hollister","kaylee","margaret","grandma","143143","donkey","salvador","lovehurts","stars","rodriguez","jason1","sanchez","boston","thuglife","181818","patito","thumper","piolin","theresa","derrick","helena","dianne","sweet1","joseluis","aquarius","dancer1","ashleigh","aaaaa","diosesamor","bigboy","danger","brownie","phillip","sammy1","panda","maxwell","mihaela","trisha","kitty1","parker","love4ever","esther","shane","chinita","alexandru","pickles","rosebud","archie","yvonne","virginia","heart","hamster","amormio","rosario","police","gregory","frances","lorraine","marius","speedy","hayley","11223344","arnold","morena","kaitlyn","fantasy","trevor","sports","audrey","tweety1","asdfg","babycakes","sexy123","taylor1","hello123","babies","golden","12341234","black","gerrard","italia","justice","brittney","superman1","catarina","roxanne","nintendo","marco","toyota","753951","lorenzo","cuddles","yasmin","chrissy","darwin","rockme","diablo","rascal","summer1","nadine","tyler1","giggles","sofia","godisgood","dominique","rocku","happiness","jenjen","castillo","joyjoy","shorty1","russell","ghetto","wildcats","kittykat","madison1","faith","william1","pelusa","blahblah","franklin","beautiful1","college","mickey1","curtis","jocelyn","fabiola","cristo","buttons","junjun","alisha","cheer","kayleigh","gilbert","unicorn","rooney","rochelle","babygurl1","julio","cricket","macmac","singer","montana","cuteko","vanilla","1qaz2wsx","winston","merlin","hershey","philip","bloods","bigdaddy","sarita","slayer","gabrielle","naughty","mississippi","therock","friends1","tiger","pikachu","soledad","mickeymouse","marilyn","shithead","7654321","sapphire","busted","johanna","yolanda","gwapako","123654789","prettygirl","pickle","emerald","warren","jacob","nascar","jellybean","elizabeth1","dragons","pretty1","love13","ramona","australia","camilo","scotty","pink123","bismillah","pedro","douglas","pinkie","holas","yoyoyo","photos","briana","carla","lucky13","callum","9876543210","shirley","lavender","hilary","iceman","aurora","goddess","erick","ihateu","janelle","loveme2","asshole1","dylan","little","watermelon","copper","rahasia","breanna","lourdes","juancarlos","PRINCESS","tania","yellow1","cheer1","latina","lovergirl","windows","papito","hunter1","010101","22222","ranger","krystal","idontknow","kittens","rocky1","madonna","diamond1","damien","iluvme","emanuel","teamomucho","norman","poohbear1","kingkong","171717","goldfish","cindy","flower1","music","houston","spanky","wicked","belinda","iloveu1","ballet","rangers1","valentine","hotgirl","peanut1","boogie","cuties","teacher","volcom","yahoo","142536","charlene","liberty","babyphat","shaggy","caramelo","selena","mookie","phoebe","incubus","baby123","special","wendy","coolgirl","lovelife","billy","0000000000","connie","myname","loulou","chelsea1","maymay","handsome","alexa","a12345","buster1","lucero","richie","steelers","crazy1","marlboro","kristin","love1","chicken1","1435254","rayray","angelita","sniper","paula","peter","arthur","tommy","walker","guadalupe","124578","kissmyass","goober","linkin","candy1","esmeralda","peace","dayana","marisa","iloveme1","converse","random","ramirez","champion","sexybabe","angel123","nathaniel","spongebob1","harry","2cute4u","atlanta","sassy1","falloutboy","molly1","jesse","dianita","1111111111","gothic","sassy","161616","eunice","nissan","sexy12","12345a","0000000","family1","hotchick","080808","giovanni","sagitario","preston","kelvin","juventus","danica","shutup","cutegirl","lacoste","campanita","winner","password123","snuggles","fatboy","realmadrid","951753","iverson3","stefan","leelee","ronaldinho","erica","austin1","skippy","bernard","newcastle","esteban","maribel","moises","thomas1","spirit","tiger1","missy","mahalkoh","blueeyes","fresita","hotpink","pakistan","tequieromucho","loser1","taytay","honey1","playboy1","soulmate","celticfc","ecuador","tagged","michel","carrie","helpme","judith","michele","kennedy","brandi","nancy","111222","stanley","arlene","lunita","pierre","landon","rachelle","maurice","darius","newlife","Password","nicola","southside","hermione","282828","unique","mackenzie","cooldude","alexia","99999","ernesto","domino","cosita","france","hummer","mamapapa","coolcat","morales","edgar","nigger","katelyn","rodney","dimples","bunny","chocolate1","gonzalez","children","father","starlight","dillon","rivera","eclipse","fender","moonlight","iluvu","viviana","something","esperanza","marlene","cassidy","abcde","softball1","234567","sunset","love22","godbless","garrett","kathryn","77777","pitbull","baby12","romance","chopper","fucku","ingrid","blue123","clover","groovy","warrior","smudge","134679","allstar","annie","goldie","swordfish","snowflake","ricky","yugioh","blabla","shasha","theone","redsox","dragon1","ballin","karate","ragnarok","doraemon","daisy1","freddie","julie","puppy","success","paramore","online","runescape","wizard","geraldine","jermaine","blue22","dimple","romania","bhaby","loveless","meghan","bitchy","thailand","alonso","tweetybird","mykids","bella1","jefferson","cherries","maggie1","seventeen","coconut","mariela","emotional","computer1","sponge","smallville","peluche","serena","poopie","cheryl","gladys","punkrock","191919","mexico1","cameron1","amber1","262626","green1","andreita","ximena","asdasd","boricua","basket","vanesa","janjan","070707","marjorie","kendra","kaykay","joyce","destiny1","blueberry","john316","kevin1","acuario","butthead","mollie","harmony","jupiter","whatever1","athena","kirsty","brother","granny","aileen","negrita","abraham","angelbaby","booboo1","doggie","michaela","dipset","blacky","bonbon","alexis1","danilo","munchkin","patrick1","samantha1","mikey","cheeky","babyboy1","mmmmmm","ilovemyself","wrestling","dragonfly","guillermo","chandler","nathan1","lasvegas","miracle","bintang","love69","harrison","casey","harley1","alfonso","moreno","qwe123","jillian","eternity","stinky","yourock","maureen","bullet","asdfjkl;","jazmine","manunited","carlo","duncan","heyhey","seven7","christy","rock you","iloveboys","drowssap","159951","bailey1","karlita","bogdan","lilwayne","supergirl","rachael","catalin","melisa","bugsbunny","hollie","kenny","wallace","jaguar","emilio","makayla","starfish","welcome1","holly","jennifer1","alianza","mathew","alfred","pepper1","juanita","knight","violeta","puppylove","baxter","gymnastics","ilovechris","8675309","caramel","virgin","goodgirl","milkshake","mckenzie","redrose","1password","holiday","fishing","steven1","santana","kenzie","badass","baseball1","logitech","manuela","monday","ingeras","katkat","ginger1","blackie","aubrey","felicia","estefania","estrela","popeye","love14","godislove","jajaja","keisha","america1","scrappy","freaky","friday","elena","lenlen","deanna","geminis","colleen","danny1","ariel","holden","hehehe","frank","sublime","scott","2hot4u","coolio","danielle1","sarah1","florin","joseph1","killer1","alaska","gordon","teddy","lizard","argentina","callie","aaron1","legend","valentin","futbol","mayra","yankee","lifehack","chelle","sasha","vegeta","mermaid","luisa","roland","myangel","lampard","monika","rihanna","fiorella","melissa1","billie","manson","sugar","clifford","denisa","yesenia","sailormoon","love11","ludacris","junior1","jonjon","fucku2","ABC123","microsoft","joana","clayton","kathy","forever1","kirsten","corona","golfinho","change","dragoste","gonzales","falcon","maxine","josephine","dramaqueen","yvette","carol","stevie","richard1","vivian","passport","tracey","platinum","arianna","kisskiss","carito","bruno","henry","honduras","shalom","carina","sexylove","thegame","computadora","maximus","ronaldo7","morris","fergie","ilovematt","berenice","momdad","noodles","dalton","eastside","steph","272727","divina","liverpoolfc","dwayne","redneck","orange1","lollol","ilovejosh","howard","rocket","lovesucks","password12","joejonas","rebeca","simona","asd123","mibebe","88888","1212312121","annette","love101","wolves","conejo","963852","nacional","warriors","evanescence","hotmama","yousuck","loveu2","fabulous","kawasaki","aventura","cristi","tequila","bubba","phantom","marcelo","stewart","cristiano","spooky","jersey","heather1","smelly","dolphin1","hercules","cleopatra","brayan","pablo","123","martina","saints","gabby","pirates","fernandez","denver","raiders1","brendan","luisito","freedom1","marines","mahalq","blanca","555666","motherfucker","maryann","snowman","jennie","drummer","cheetah","love21","yanyan","kenshin","alvin","leonard","cracker","turkey","cuttie","tricia","sexy69","freckles","medina","romeo","missy1","cherry1","kendall","fuckit","prettyme","randy","bubba1","roberta","agosto","everton","candice","juliet","suzanne","carlos1","single1","456456","steve","090909","kieran","madeline","jesus7","nightmare","hamilton","antonia","laptop","mother1","surfer","german","poop","messenger","kimkim","iluvyou","filipa","honeybee","castro","private","jonas","love23","doodle","grandad","celine","mustang1","edison","isabelle","romero","mandy","jetaime","julia","Princess","cintaku","pancho","jacqueline","amore","logan","promise","anything","charmaine","colorado","newyork1","alvaro","student","qazwsxedc","budlight","rocknroll","mystuff","jeremy1","trinidad","leticia","yomama","melinda","smokey1","shiela","020202","paris","ruben","jacob1","apple1","picture","wordpass","dulce","stormy","sweetgirl","loveyou2","sayangku","ashanti","angel12","harris","confused","blessed1","peaches1","tootsie","franco","andreia","ericka","taekwondo","ismael","insane","alexandre","chingy","cowgirl","juanito","nokia","cheese1","pink","sixteen","iluvu2","precious1","angel2","arcangel","ganteng","scruffy","biatch","delete","punkin","1bitch","jerry","valencia","pussy","loveable","swimmer","florence","rainbow1","shawn","system","poison","shauna","galaxy","pavilion","a1b2c3","forget","gizmo","gunner","minime","malibu","hitman","rommel","marion","renato","applepie","divine","thalia","virgo","emily1","mnbvcxz","jesusfreak","penelope","chucky","gizmo1","jackson1","bobmarley","dorothy","queen","psycho","redhead","madrid","felicidad","lynlyn","babykoh","kayla1","sisters","sidney","sexybaby","454545","rolando","tasha","alabama","lizbeth","nemesis","doctor","ilovemike","triskelion","loveyou1","dietcoke","maemae","hazel","321654","cellphone","aldrin","country","hihihi","lovers1","rey619","aries","slimshady","liverpool1","germany","stitch","lauren1","philips","bryant","pimpin1","ewanko","skyler","dondon","beatrice","stuart","bigred","maimai","american","cristal","hanson","maricel","soloyo","fatcat","rowena","gibson","skipper","sherry","getmoney","vodafone","paige","jonathan1","nataly","babes","chloe1","stardust","password3","oscar1","jonasbrothers","greenday1","eminem1","monalisa","motocross","nickjonas","moocow","amazing","eddie","magandaako","church","cruzazul","super","lucas","robinson","laurita","abcdefgh","kagome","qwerty123","bernie","morgan1","weed420","beverly","kakashi","paolita","jamie1","filipe","xander","grapes","irock","bonjovi","theused","mypassword","princes","devils","morado","tattoo","cinta","edwin","milton","shanice","shannon1","conner","avril","marijuana","cinnamon","121314","flamingo","scooby1","13579","escorpion","benson","myfamily","mobile","regine","famous","love15","sprite","broncos","theman","telefon","jenna","rakista","eleven","misty","DANIEL","password!","nevaeh","marimar","camaro","allen","potpot","ilove","johana","tonton","falcons","noodle","marine","tomtom","trandafir","420420","wonderful","jenifer","angel13","lifesucks","madden","bobby1","dance1","snoopy1","bowwow1","chivas1","suzuki","payton","wolverine","georgina","tinker1","fuckoff1","respect","zoey101","pencil","iloveme2","raven","marcel","katie1","aishiteru","jaime","makaveli","personal","cowboys1","michigan","bamboo","lestat","007007","black1","fofinha","corvette","abercrombie","emerson","newport","cathy","enigma","love143","pink12","billybob","astig","georgiana","alondra","lionking","candyfloss","brittany1","pinky1","winniethepooh","050505","poncho","g-unit","303030","alyssa1","window","donnie","emilia","deborah","asdfasdf","kittie","iforgot","cedric","brazil","amalia","nathalie","iloveryan","langga","963852741","bigdog","beatles","manman","mypics","hammer","devil","angeleyes","antony","sheryl","soccer12","lillian","spoiled","monkey2","292929","zzzzzz","alina","princess2","meandyou","hotboy","renee","sunday","nelly","samsam","kimmie","shawty","behappy","krissy","magic","simpson","marianne","powers","yankees1","dingdong","boobies","chelsey","emogirl","mikaela","denisse","ssssss","tiffany1","music1","dickhead","scooter1","donna","sonia","chantelle","bratz","wedding","capricornio","elamor","puertorico","wisdom","bonjour","magdalena","irene","skateboard","octubre","noviembre","1123581321","carebears","arizona","ilovemom","soccer10","desire","kkkkkk","nikki1","brasil","scarlet","graham","pillow","naynay","gabriella","kenken","pandora","lennon","jesse1","brianna1","lacrosse","bombon","frogger","maritza","skyblue","southpark","ilovejoe","anjing","jamjam","savage","sexy13","chikita","asawako","mitch","duckie","armani","sexyboy","mariajose","victory","azerty","xiomara","batman1","ivonne","girlfriend","believe","indian","philly","hacker","baby","subaru","lovable","hannahmontana","lopez","jjjjjj","rodolfo","ilovepink","english","saturn","sparkles","sucker","445566","crystal1","shamrock","789789","mylove1","perrito","smackdown","timmy","charity","conejita","rockers","marcia","josue","BABYGIRL","bluesky","spring","pepito","biscuit","135790","bobbie","sherwin","lol123","kermit","suckit","nadia","apollo","denden","astrid","qwertyui","racing","jewels","queenie","jenny1","naruto1","muhammad","killua","zidane","toshiba","burbuja","leandro","eileen","campbell","12344321","jester","kristy","donovan","dalejr","peachy","kellie","rooster","scarlett","blingbling","dakota1","playstation","loquita","lilbit","thankyou","missyou","george1","secret1","johnpaul","coldplay","surfing","avatar","sexsex","flaquita","maddog","mittens","lilman","cotton","778899","chelseafc","dylan1","565656","honeys","babygirl2","noelle","anastasia","killme","retard","barbie1","poppy","priscilla","jimenez","joejoe","longhorns","danielita","soccer13","jeanette","sexygurl","cloud9","898989","boyfriend","brayden","kickass","rammstein","porter","tarzan","carmelo","panasonic","sophie1","celtic1888","twister","libertad","leonel","gators","nofear","laguna","estrellas","krista","terrell","losers","rosemary","borboleta","delacruz","knights","malcolm","aol123","gwapa","bluemoon","jimena","little1","ladybug1","johnny1","corina","diciembre","hallo","jared","gordita","johnjohn","player1","johnnydepp","titans","death","louie","lemons","power","mercury","princess12","mariam","pinklady","rosie","maria1","hassan","senior","jimbob","gangsta1","redred","gillian","lamejor","tabitha","althea","pokemon1","1478963","amizade","mohamed","kingdom","megan1","belle","sexyback","sugar1","pookie1","dawson","shibby","soccer7","romina","carson","030303","skeeter","classof08","alice","spunky","trigger","pizza","latoya","corey","kimberley","nugget","nibbles","canela","netball","shelley","blood","sexy101","sweetie1","allan","060606","keith","jimmy1","darlene","francesca","paulo","asdf1234","1234qwer","soccer11","jeffhardy","cristy","bernardo","peanuts","love16","teodio","qwaszx","alexandria","becky","lilly","bautista","vicky","jakarta","12121212","africa","pepsi1","jeffery","skylar","manolo","cartoon","nellie","qwertyu","renata","packers","password7","daniella","daphne","smile1","cosmin","987456","celular","samurai","guatemala","manzana","herman","rhiannon","declan","mamacita","patty","flakita","pirate","star123","pinkpink","stupid1","brooklyn1","bastard","margarida","angeline","hollister1","dandan","666999","simon","russel","toffee","clarinet","mallory","halloween","pippin","jazzy","qweasd","classof09","bloodz","attitude","sadie","pornstar","runner","battle","megaman","libra","forest","kiara","senior06","joker","lizeth","lottie","brutus","keyboard","acmilan","christian1","9999999","ilovesam","peyton","digital","dragonball","bridget","skate","5555555","charly","squirt","brian1","traviesa","ilovejohn","alvarez","daredevil","lilian","misty1","married","ethan","deftones","outlaw","soldier","desmond","ilovenick","tootie","44444","happy123","qqqqqq","betty","florida1","pandas","lilfizz","logan1","patrice","ilovehim1","shayne","angels1","emopunk","carmela","eliana","tommy1","yandel","heartbreaker","love08","pasword","rockstar1","gymnast","valentino","sunny","mamasita","catcat","sadie1","girlie","avrillavigne","loredana","jehova","onlyme","larissa","joaquin","faithful","evolution","lucia","carmel","nigga","mivida","carolyn","monkey12","detroit","travis1","tigers1","diane","collin","159159","female","faith1","chemical","mattie","manila","patricio","morrison","jeanne","stefania","sandy1","elliot","my3kids","wassup","redskins","firefly","warcraft","natalie1","water","honda","456852","lanena","nicoleta","vikings","kisses1","papamama","cheesecake","prissy","infinity","salazar","frosty","ellie","captain","glamorous","septiembre","bernadette","mumdad","pinkpanther","lavigne","puppy1","teddy1","girlpower","mexican","spitfire","georgie","sexy1","andrea1","thirteen","fuckers","porsche","sexy","eastenders","hellomoto","love07","zombie","razvan","cat123","candace","kimmy","dumbass","jericho","indonesia","nayeli","mygirl","angelic","pepsi","naomi","jamesbond","33333","backspace","bebito","charmed1","nicholas1","lemonade","bhabes","kawaii","derek","murray","randall","carrot","meagan","potato","rainbows","hilaryduff","isaac","unknown","shania","charley","sylvester","55555555","oranges","forgot","victoria1","hinata","elvis","JESSICA","matias","siobhan","thompson","melina","fucking","dougie","bunny1","porkchop","lexmark","digimon","spike","future","westham","yahooo","brooke1","clarence","ilovealex","kristian","extreme","telephone","shortie","mushroom","alexander1","texas1","tigger2","iloveben","rebecca1","lancer","chrisb","mamamia","cherokee","manchesterunited","penguins","louise1","habibi","chipper","beanie","wildcat","pollo","j123456","CARLOS","miguelito","mikey1","soccer2","258456","medicina","flames","airforce","malachi","bleach","febrero","solomon","anime","blondie1","alex123","love01","margie","renee1","irish","braves","enamorada","lucifer","dallas1","sterling","1lover","explorer","gundam","jackie1","security","together","giselle","bumblebee","NICOLE","blazer","perros","watson","iamcool","tamahome","goodies","cutiepie1","master1","7894561230","holland","lassie","jessie1","fucklove","tobias","babyangel","rocio","malaysia","nenalinda","poochie","amarillo","china","cartman","benjie","jaypee","domingo","strong","chickens","whiskers","yadira","digger","soccer9","paolo","terry","14789632","iloveyou3","lewis","skater1","daddyyankee","secrets","popstar","blessing","adelina","monkey123","matematica","playmate","oklahoma","littleman","poopy","sexy14","vanessa1","cassie1","monster1","ANGEL","nestor","osiris","salome","mustangs","gerardway","felix","girlsrule","annabelle","magnolia","darrell","lincoln","stonecold","reading","i love you","wanker","123456j","bombom","goodbye","kaitlin","susan","mybaby1","killers","renren","babybaby","freak","mommy2","clarissa","goodluck","julieta","123456789a","perro","josiah","vicente","raluca","pudding","casanova","gracia","fucker1","napoleon","angelz","lance","osito","nicky","mountain","floricienta","paopao","blue12","colton","sooners","blackrose","redbull","simba","janeth","mystery","mommie","iamthebest","pumas","penny","theking","sabina","richmond","sally","kikay","roseann","therese","siemens","bluebird","darryl","maricar","caitlyn","flipper","gabriel1","froggie","22222222","roses","teamobb","lebron","flowerpower","sandiego","reynaldo","forever21","junebug","mumanddad","latino","seven","gemma","classof07","bunnies","tacobell","753159","klapaucius","glenda","bobesponja","jesus777","matilda","frankie1","samara","chester1","dayday","sasha1","cortez","567890","99999999","crazygirl","washington","robin","1princess","pangga","clinton","angel7","angel01","abc1234","rachel1","pinkgirl","central","charles1","arsenal1","memories","dream","amylee","poodle","sharks","dangerous","lamont","love06","stoner","kelly1","summer06","chris123","butterflies","dollar","hillary","araceli","damaris","hotrod","love1234","kaiser","babybear","m123456","metal","bentley","rootbeer","lesley","redrum","1loveyou","godzilla","love10","fireman","gordito","billy1","carpediem","pazaway","changeme","123457","burton","banana1","powerpuff","midnight1","chaparra","chuckie","janet","dalejr8","catwoman","baby13","adrienne","webster","hanna","violin","horses1","guerrero","pa55word","shiloh","whiskey","tottenham","q1w2e3","ASHLEY","laloca","mychemicalromance","ANTHONY","werty","1122334455","aberdeen","youandme","molina","adriano","koolaid","jojojo","hooters","fanny","223344","rusty1","milena","sheldon","sleepy","1234abcd","locura","dolores","yahoo1","whatsup","LOVELY","heaven1","jessy","redhot","fallen","becca","brebre","monse","monique1","babygirl12","marita","lebron23","casey1","julissa","bowling","calculator","browneyes","rebekah","lightning","rebels","boomboom","yourmom1","britt","qwerty12","starbucks","olimpia","alucard","mikayla","humberto","sylvia","aaliyah1","dragonballz","fatass","magodeoz","cookies1","maniez","789123","321321","shayshay","scottie","science","candycane","chobits","reyes","trunks","eduard","angelique","voodoo","xxxxx","2sexy4u","johnathan","123456m","asdfghjk","lesbian","snowwhite","slipknot1","hamish","krishna","ilovejames","button","5555555555","rangersfc","******","wonder","limegreen","maddison","school1","usa123","patriots","eleanor","mariano","grecia","Jessica","terrance","raider","iloveadam","edward1","chino","meowmeow","chavez","indiana","aguilar","shelby1","66666","786786","chase","rogelio","blablabla","te amo","access","blackcat","carajo","warning","jhonatan","jeter2","camera","dookie","mirela","tyson","gareth","claudio","micaela","imissu","sam123","gameboy","singing","turner","charming","loveko","pacman","yazmin","holahola","justdoit","marcus1","vargas","love24","fuckyou!","363636","kristel","password.","lovehate","verito","wanted","blake","popcorn1","boobie","deathnote","danielito","memory","penis","beaver","evelin","nevermind","147896325","friendly","kissme1","gunners","umbrella","misterio","MICHAEL","zachary1","323232","lololo","tantan","mafalda","rosemarie","pussy1","celtic1","haley","rolltide","oliver1","mahalcoh","cashmoney","bandit1","shayla","q1w2e3r4","clouds","rosado","engineer","smarties","larisa","cougar","sampson","larry","jazzy1","selene","dannyboy","909090","starburst","holly1","riley","rakizta","quincy","prayer","livestrong","jayden1","mildred","weezer","ilovesex","funny","jesica","iminlove","antonio1","viridiana","98765","sk8ter","denise1","firebird","haters","hellboy","password5","seanpaul","rusty","casper1","laura1","juancho","agustin","ulises","coolness","sinead","someone","bob123","juggalo","jaycee","gatinha","jomblo","alex","fisher","buddha","versace","monroe","040404","josefina","foster","analyn","courtney1","compaq1","12qwaszx","elliott","orlando1","flowers1","hogwarts","business","soccer3","56789","billiejoe","vagina","123456789123456","greeneyes","iloveyou.","monkey7","sexychick","wayne","pucca","griffin","queens","treasure","maroon5","kingston","kenny1","energy","cinthia","emiliano","survivor","minnie1","elisha","stargate","aussie","placebo","lipstick","12369874","iloveyou7","helen","watever","memphis","biggie","boycrazy","freeman","kipper","thesims","philippines","147147","holla","ciara","gateway1","rocks","cougars","dddddd","samira","roger","kobe24","angel11","soccer4","baller1","badminton","reebok","lynette","roscoe","bbbbbb","212224","skinny","369369","hottie101","rupert","fercho","gracie1","hurley","bookie","johncena1","ronron","herbert","pppppp","jingjing","123698745","meredith","mylene","serendipity","teadoro","neopets","whocares","sexybeast","yummy","cupcake1","yenyen","blonde1","artist","rugrats","yumyum","fireball","bradpitt","dracula","amoremio","love18","stargirl","simba1","heartbroken","fluffy1","Michael","general","mister","panama","chiqui","rebelde1","girls","puppys","leilani","313131","787878","angeli","rukawa","poiuyt","ILOVEU","timberlake","felicity","honda1","ilovedan","inuyasha1","amsterdam","blades","tiesto","pleasure","khulet","martin1","eliza","redman","mouse","airforce1","jordyn","loveit","walmart","vladimir","shanna","secreto","kitten1","bacardi","pelota","hendrix","killa","andreas","poppop","collins","penny1","waters","freestyle","stefanie","soccer14","trenton","chucho","Password1","1234560","maximo","doggy","sunrise","teamobebe","patience","my2kids","brodie","love09","shawna","marquis","estefany","alone","TEAMO","bishop","shawn1","lakers1","elijah1","brandy1","minerva","blackjack","babypink","pringles","tiago","kontol","asakapa","vinnie","paintball","yasmine","myhoney","gutierrez","playboy123","mendez","qazxsw","loveforever","fotos","jonalyn","aimee","snoopdog","adonis","wateva","mason","andrey","vampires","thanks","chantal","raven1","mozart","summer07","giants","badger","789654","guitar1","pablito","candygirl","mario1","angelface","villanueva","lilangel","amote","dustin1","prince1","nolove","lovegod","beaner","webcam","snoopdogg","JORDAN","shitface","cheerleading","rebel","pumpkin1","looney","gonzalo","marihuana","muppet","superstar1","olivia1","snakes","puppydog","19871987","harry1","solange","7895123","smarty","dulcemaria","juicy","maryjoy","texas","party","raphael","underground","dodgers","striker","boricua1","123456k","tulips","tomboy","spikey","trooper","romeo1","1314520","aliyah","ilovedavid","01234","dog123","snickers1","apples1","movies","25252525","street","emelec","sunny1","jackass1","ethan1","654123","highschool","buffy","cherish","sherman","goodboy","juanjose","princess13","mummy","zxcvb","stephen1","maryrose","jumong","candle","imcute","ironman","fresa","anabel","amethyst","navarro","woaini","sweetiepie","jonathon","trinity1","franky","guinness","muffin1","martini","spartan","leeann","gretchen","lillie","shane1","bribri","idunno","wazzup","andromeda","bloody","francine","caleb","sweetlove","corazones","sexy11","bobbob","bitch123","grandma1","ferreira","selina","honesty","nguyen","rovers","skittles1","sexy15","deadman","turtle1","giraffe","elvira","ernest","devin","panda1","jhonny","sirena","dieguito","oswaldo","pendejo","benji","1a2b3c","pink11","sexbomb","morangos","lavinia","angelgirl","pebbles1","angela1","carlita","love4u","adrian1","619619","qwer1234","19891989","icecream1","garden","alegria","beauty1","lilone","craig","imcool","my2girls","jesus123","ANDREA","federico","kaycee","thunder1","scott1","spiderman1","kangaroo","markie","kathmandu","johndeere","gwapo","ilove?","venezuela","blueangel","pink13","star","herrera","myheart","gianna","myboys","mygirls","claudiu","education","aerosmith","imsexy","butter1","ironmaiden","account","pompom","fighter","twins2","321654987","alinutza","rashad","because","buffalo","reggae","anakin","superpets","cheekymonkey","max123","bounce","maxmax","raerae","chippy","einstein","miguelangel","mike","temple","pereira","angel3","love17","printer","march","senior07","chinito","hongkong","benny","makeup","madmax","chantel","misael","immortal","queen1","singapore","dante","joaninha","hunnie","escape","summer08","karolina","angel5","tangina","jungle","topgun","floppy","badboys","victor1","tarheels","coolman","smirnoff","homero","eighteen","miley","gwapoko","bigdick","happydays","soccer5","isabela","boxing","presario","bradley1","diogo","darnell","bigbird","kentucky","chunky","stephy","aguila","lashay","pisica","kamote","angel22","tanya","timothy1","peaceout","llllll","gotohell","tammy","monopoly","tyson1","sweetangel","jasper1","jarule","antonella","silvana","eddie1","papichulo","fucku1","password11","ivette","woohoo","herbie","burger","sexual","sparrow","brokenheart","yuliana","narnia","francia","terrence","peluchin","milkyway","horse","imagine","lizzy","smiley1","adolfo","villevalo","polaris","monita","shasta","glenn","muerte","negrito","bond007","ichigo","ilovemymom","jaylen","goodcharlotte","laurence","babydoll1","french","chico","ionutz","davids","leigh","photo","honeykoh","vince","tripleh","homies","glamour","juanpablo","eagles1","nelly1","19921992","soylamejor","silver1","stefany","iubita","ramones","cornelia","tribal","alesana","nigga1","tropical","whisper","smile4me","reagan","metoyou","april1","caballo","family5","stephanie1","slide","angel14","annmarie","yahoo.com","keegan","cabbage","revenge","startrek","ashlyn","julieann","cheska","jackson5","pancakes","gabby1","ilovemyfamily","calderon","auburn","finalfantasy","MICHELLE","predator","daughter","class09","breezy","dipset1","ilovejake","journey","classof06","trouble1","marquez","newton","karito","adrianna","mission","astonvilla","dodger","dodong","sexygirl1","james123","1jesus","sporty","youtube","maradona","buddie","zxcvbnm,./","ricky1","jesussaves","history","green123","sexyass","malagu","my2boys","pegasus","packard","popopo","ionela","princess7","consumer","riley1","tyrell","bratz1","geronimo","1qazxsw2","boobear","maddie1","bumbum","viking","hudson","marianita","pioneer","allie","grumpy","musical","contraseña","kambal","silent","luciana","running","winxclub","hearty","benito","cinthya","liezel","badman","christie","smooth","bigman","cancel","dublin","cherie","peanutbutter","zamora","delicious","sixers","jesusc","candyman","leonor","mafer","itachi","a1b2c3d4","twinkie","clueless","patches1","chevelle","addison","ralph","sparky1","mydear","password13","topher","trumpet","savannah1","69696969","fiesta","angel101","kristi","mason1","cheers","estela","bennett","backstreet","abcd123","enter","jessa","jensen","brown","505050","fourteen","arianne","rosie1","rastaman","naenae","369852","password4","pamelita","jologs","godfather","lilred","baby14","island","babycoh","sailor","ravens","savanna","indigo","blizzard","playboi","pingpong","pink22","ilovemark","mom123","fatman","friends4ever","xoxoxo","aguilas","livelife","luisteamo","praise","alissa","monkey3","tornado","timmy1","control","chase1","fuckface","spike1","beloved","timber","19861986","nichole1","alanna","123987","jhenny","harlem","gordon24","lovingyou","summertime","crazy4u","543210","ritinha","chinchin","innocent","lucian","hitler","dudley","haylee","jaiden","delfines","monitor","bhabie","roxygirl","soccer15","walalang","devil666","mileycyrus","ariane","rosales","rhonda","dwight","neneng","salinas","lilmama1","emokid","midget","ilovetom","23456","PASSWORD1","madness","pancake","salvation","oooooo","dominick","oliveira","broken1","doglover","jessika","irving","gandalf","froggy1","punker","booger1","soccer8","pokpok","demons","poptart","grace1","ilovejason","damion","fcporto","principe","ioana","manager","mayang","molly123","princess3","angel21","my3sons","cielo","zander","prinsesa","asdfghj","kassandra","magaly","chocolat","turtles","oldnavy","choclate","pearl","pothead","souljaboy","ramon","bigbrother","ranita","chihuahua","111213","thatshot","reaper","elmejor","awesome1","QWERTY","dutchess","momanddad","ibanez","gunit","ninja","mango","lorenz","benedict","sebas","soccer6","jesuss","garnet","pampam","poppy1","luckydog","fabio","disturbed","babygirl13","bearbear","colombia1","123789456","cristiana","bellota","candies","aaaaaaaa","newzealand","bertha","samanta","222333","emachines","millwall","killbill","monkeybutt","jacky","coyote","information","denzel","tierra","cierra","itzel","barbiegirl","maiden","chris12","original","assassin","kelley","madman","hawaiian","alessandro","peter1","blue","Daniel","lorenita","marygrace","classic","karencita","james23","people1","coleman","morenita","kittys","debora","iulian","celina","jesuslovesme","apple123","waterfall","cowboy1","darkside","willy","passwords","kamikaze","katty","complicated","perlita","monkey13","gisela","iloveyou12","star12","mohammed","birdie","redroses","peekaboo","gerrard8","gotmilk","angell","jones","hotshot","paige1","1angel","cooper1","estrada","afrodita","baby08","frederick","edwards","xavier1","hamtaro","nature","lionel","alicia1","piggy","venice","graciela","looser","sharpay","gamecube","class07","bighead","tennis1","velvet","siempre","doggies","258963","1blood","cookiemonster","biology","colt45","hotbabe","duchess","angel16","water1","jelly","blue32","monica1","baby1","sandrita","wachtwoord","laurie","kamila","pineda","123456s","letmein1","silvestre","qweasdzxc","ilovedogs","melany","blue13","kahitano","sexy01","gwapoako","oakland","19931993","111111111","makulit","redwings","marielle","miguel1","jonny","linda1","savior","satan666","mcdonalds","allyson","brooks","thinkpink","wordlife","lovebug1","JASMINE","groovychick","pollita","omarion1","mysterio","angel10","tortuga","pizza1","chelsie","sandoval","marsha","nicole2","eatshit","lollies","hibernian","annie1","teresita","monkeys1","budweiser","cannabis","guitarra","steph1","courage","cabrera","solotu","Jordan","antoine","mifamilia","godlovesme","target","kansas","lowrider","marta","Michelle","doodles","nobody","bobcat","cool123","dejavu","akatsuki","ferret","create","bessie","boobs","mommy3","jomar","rafaela","reddog","avalon","erwin","hoover","brendon","ilovekyle","deejay","mandy1","sahara","Nicole","sexybitch1","integra","georgia1","hello12","19851985","grandpa","crackers","mercado","s123456","carissa","catfish","MONKEY","semperfi","alvarado","angelus","elisa","honeyz","marvel","keekee","corbin","family4","usher","subway","eragon","search","pinkish","newman","ezekiel","catch22","wwwwww","elisabeth","mmmmm","palmtree","bball","capslock","monyet","friendsforever","skywalker","richelle","labebe","000001","nookie","sassygirl","manny","maricris","happyfeet","mariah1","delgado","oicu812","sosexy","sparks","momof3","littlebit","twiggy","squall","estefani","mongoose","buffy1","tanisha","pisicuta","counter","meggie","elefante","aquino","princess123","qaz123","bitch69","labtec","hello2","19941994","pass123","belleza","valery","sweety1","77777777","matty","chargers","corey1","glasgow","tenten","bubulina","squirrel","mybabies","maxpower","hailey1","smitty","louis","aquamarine","nineteen","nicole12","maricela","fabolous","hunnybunny","nickolas","negro","latrice","poiuytrewq","snowboard","chico1","scream","alessandra","maisie","hondacivic","bryan1","magnum","baybee","aleja","carebear1","mamama","eloisa","techno","independent","lalito","volume","141516","luckyme","metalica","cancun","cobain","southern","aragorn","devon","1q2w3e4r5t","rancid","juanes","arielle","shaun","candie","volley","ash123","priscila","cheyanne","bubble1","elvis1","hustler","lilly1","fairies","leopard","bigfoot","flipflop","peace1","minniemouse","teetee","notebook","AMERICA","bonnie1","ortega","cutify","moose","bernice","nicolle","bluebell","sierra1","gilberto","anarchy","tasha1","hilton","ripcurl","connor1","terminator","onepiece","dionne","dorian","carnell","sandra1","florentina","LOVEME","chicky","catdog1","chronic","amorsito","padilla","lovemom","snowball1","pizzas","chicks","fossil","beach","telefono","nanita","kimerald","wonderland","fantastic","josie","lights","987456321","gordo","escola","beebee","bitches1","twins","deandre","smokie","chicago1","splash","disneyland","ibrahim","teddybear1","lovelygirl","burberry","ignacio","test","143444","paixao","camelia","ramiro","baby07","jeffrey1","456321","snapple","asasas","gracey","gorillaz","TWEETY","hello!","memyselfandi","kassie","venus","guzman","pooper","bluestar","angel15","hellothere","happybunny","nessa","booty","putangina","toronto","jamielee","jehovah","bunnyboo","bigmama","gogogo","baby11","crybaby","joselito","fresas","Anthony","element1","sexy16","joselyn","monkey11","xtreme","babygal","loraine","kameron","alonzo","tomato","lovehim","chiquito","suicide","minina","abegail","1truelove","alohomora","fraser","diamante","rasta","abigail1","casino","JOSHUA","bhabycoh","tucker1","pandabear","tracy","hellow","gavin","nikolas","computador","lissette","vernon","blanco","k123456","wolfpack","henderson","a1234567","baby01","muneca","giovanna","edgardo","queenbee","jamila","jesusislord","magic1","candys","yankees2","Danielle","thelma","anaconda","roberts","jarvis","gerson","powder","chuchu","dixie1","blink","hardrock","damnit","sexymama1","sonny","dottie","ojitos","anahi","Jennifer","lilkim","horse1","lucille","godsmack","jazzie","smith","JUNIOR","angel07","young1","honest","1029384756","planet","chinese","hithere","lamborghini","Liverpool","ESTRELLA","soccer16","western","castle","class08","helloo","smile123","murder","loveis","deleon","lobster","784512","japanese","labrador","yomomma","seattle","steve1","ilovecats","raymond1","cutie123","stephany","monmon","escorpio","balong","tanner1","09876","picasso","university","lloyd","pacheco","benjamin1","foxylady","julian1","alex12","carola","chandra","smithy","stronger","alfie","lianne","sabrina1","redsox1","universal","jerson","336699","kitty123","wrangler","525252","braveheart","JESUS","monserrat","happyday","JUSTIN","shadmoss","sandro","disney1","princess11","rosalie","roderick","224466","jerico","nightwish","spencer1","carlito","1a2b3c4d","BRANDON","cccccc","888999","angie1","alemania","angel23","marques","loved1","preety","celica","harriet","kendrick","januari","june23","dolphins1","campos","micah","sexyred","isaiah1","amerika","......","houston1","tomcat","crimson","heavenly","lacrimosa","italian","heyheyhey","PRINCESA","rabbits","lilromeo","lickme","noelia","sausage","Tigger","zxcvbnm1","andre1","trojans","apache","durango","6543210","spongecola","123456c","onelove1","hotlips","sandman","super1","milano","andreina","456654","bigboy1","steelers1","honeyq","bangbang","nigger1","newpassword","badboy1","miller1","jokers","teamomiamor","matilde","19841984","dirtbike","tigger12","iuliana","revolution","FUCKYOU","metallica1","tekieromucho","jonatan","stewie","eugenia","summer05","fantasia","321456","wertyu","jellybeans","empire","june28","1234554321","speaker","natali","poetry","thesims2","bball1","ventura","abbie","sexysexy","muslim","rosalinda","soccer22","holler","spotty","teodora","bling","janina","denis","chikis","francisca","212224236","ferguson","chevy1","thursday","rockets","orlandobloom","sweetypie","sagitarius","dixie","2222222","2sweet","bonethugs","passions","wiggles","heidi","heroes","jamal","lingling","juliocesar","10203040","j12345","19881988","yessica","lokito","beetle","ladybird","polarbear","chance1","newnew","estrelinha","01234567","twisted","brianne","homer","dreaming","powell","235689","butterfly2","sexkitten","losangeles","1234567a","sexygal","gidget","blueblue","brothers","19951995","koolkat","nextel","missie","maryland","piscis","nathaly","123456t","samsung1","soleil","dogdog","starfire","october1","crips","1babygirl","bouncer","123456b","jimmie","westwood","#1bitch","rockandroll","slamdunk","brenda1","michell","lalaland","hellohello","edith","fiona","gogirl","derick","atlantis","TIGGER","sirenita","love33","phillips","bollocks","quiksilver","keepout","ihateyou1","salman","daryl","playboy69","leavemealone","iloveluke","44444444","oxford","darkstar","consuelo","camilita","MIGUEL","limpbizkit","privacy","petewentz","sonic","inferno","gusanito","golfer","jayjay1","princess01","parrot","ducky","rasmus","inlove1","kookie","biteme1","karen1","fernandes","zipper","smoking","brujita","toledo","foobared"}
    return pwd_list
end

function check_pwd(user_file, realm)
    local pwd_list = get_weak_pwd()
    local tmp_tb = {}
    local f = io.open(user_file)
    if f then
        local user,hash
        for line in f:lines() do
            user,hash = rex.match(line, [[^\s*([^=]*)=(\S*)]])
            if user and hash and #hash==32 then
                for _,pwd in pairs(pwd_list) do
                    if get_str_md5(user..":"..realm..":"..pwd) == hash then
                        table.insert(tmp_tb, {user=user,password=pwd})
                        break
                    end
                end
            end
        end
    end
    return tmp_tb
end

function formatHost(host)
    if string.sub(host, -1, -1)~="/" then
        host=host.."/"
    end

    return host
end

function debugPrint(str)
    if Debug then
        print(str)
    end
end

function handlePs()
    local cmd=[[ps -eo user,uid,group,cmd | grep "org\.jboss" | grep -v "grep"]]
    local psDB={}
    local infoStr, psMsg="", nil
    local stdConfApp="/configuration/standalone.xml"         --! 具体配置文件为${base.dir}/configuration/standalone.xml
    local domConfApp="/domain/configuration/domain.xml"     --! 域配置为${jboss.home.dir}/domain/configuration/domain.xml
    local domHostConfApp="/domain/configuration/host.xml"       --! Host配置为${jboss.home.dir}/domain/configuration/host.xml
    local jbossBaseConf, jbossHomeConf
    
    local tmp_code,tmp_msg = execute_shell(cmd)
    if tmp_code then
        return false, tmp_msg
    end
    local psCode, psMsgLi=execute_shell_l(cmd)
    infoStr=infoStr.."ps"..tostring(psMsgLi)
    if psCode==0 then
        if psMsg == "" then
            return nil, infoStr
        end
    else return nil, infoStr
    end

    for _, psMs in pairs(psMsgLi) do
        mode=rex.match(psMs, [=[-D\[([^\]]*)\]]=]) or ""
        debugPrint(psMs)
        if mode then
            if string.upper(mode)=="HOST CONTROLLER" then
                psDB.mode="domain"
                psMsg=psMs 
            elseif  string.upper(mode)=="STANDALONE" then 
                psDB.mode="standalone"
                psMsg=psMs 
                break
            end
        end
    end
    
    psDB.owner, psDB.PID, psDB.group=rex.match(psMsg, [[\s*(\S*)\s*(\S*)\s*(\S*)]])
    
    runtimeCmdSta=string.find(psMsg, "java")
    psDB.runtimeCmd=string.sub(psMsg, runtimeCmdSta)

    psDB.homeDir=rex.match(psMsg, [=[-Djboss\.home\.dir=(\S*)]=]) or ""
    psDB.baseDir=rex.match(psMsg, [=[-Djboss\.server\.base\.dir=(\S*)]=]) or ""
    jbossHomeConf=string.format("%s%s", psDB.homeDir, domConfApp)
    jbossBaseConf=string.format("%s%s", psDB.baseDir, stdConfApp)

    if string.upper(psDB.mode)=="STANDALONE" then
        conf=io.open(jbossBaseConf)
        debugPrint(string.format("The jbossBaseConf detected is %s", jbossBaseConf))
        if conf then
            debugPrint("detected!")
            psDB.confPath=jbossBaseConf
        else
            psDB.confPath=nil
        end
    elseif string.upper(psDB.mode)=="DOMAIN" then
        conf=io.open(jbossHomeConf)
        debugPrint(string.format("The jbossBaseConf is %s", jbossHomeConf))
        if conf then
            debugPrint("detected!")
            psDB.confPath=jbossHomeConf
        else
            psDB.confPath=nil
        end
    end

    return psDB, infoStr
end

function handleVersion(mode, homeDir)
    local verCmd=string.format("%s/bin/%s.sh --version", homeDir, string.lower(mode))

    local verCode, verMsg=execute_shell_l(verCmd)
    --print(string.format("cerCMd %s", verCmd))
    if verCode==0 then
        if verMsg == {} then
            return ""
        end
    elseif verCode~=1 then 
        return ""
    end
    local line = verMsg[#verMsg]
    local version=rex.match(line, [[(?:WildFly|JBoss)\s*\w*\s*(\S*)]]) or ""
    return version
end

function pwdConf(homeDir)
    local pwdConf=string.format("%s/bin/add-user.properties", homeDir)
    local pwdConfDB={}

    pwdConfFile=io.open(pwdConf)
    if pwdConfFile then
        pwdConfContent=pwdConfFile:read("*a")
        pwdConfDB.minLength=        rex.match(pwdConfContent, [=[password\.restriction\.minLength=(\d+)]=]) or ""
        pwdConfDB.minAlpha=         rex.match(pwdConfContent, [=[password\.restriction\.minAlpha=(\d+)]=]) or ""
        pwdConfDB.minDigit=         rex.match(pwdConfContent, [=[password\.restriction\.minDigit=(\d+)]=]) or ""
        pwdConfDB.minSymbol=        rex.match(pwdConfContent, [=[password\.restriction\.minSymbol=(\d+)]=]) or ""
        --! pwdConfDB.valid=            rex.match(pwdConfContent, [=[password\.restriction=(\w+)]=])
        --! pwdConfDB.notUser=          rex.match(pwdConfContent, [=[password.restriction.mustNotMatchUsername=(\w+)]=])
        --! pwdConfDB.forbiddenValue=   rex.match(pwdConfContent, [=[password.restriction.mustNotMatchUsername=([_a-zA-Z0-9,]+)]=])
        --! pwdConfDB.strength=         rex.match(pwdConfContent, [=[password.restriction.strength=([_a-zA-Z0-9,]+)]=])
        --! pwdConfDB.checker=          rex.match(pwdConfContent, [=[password.restriction.checker=([_a-zA-Z0-9,\.]+)]=])

        return pwdConfDB
    else return nil
    end
end

function getRealmName(mode, homeDir)
    local hostConf, securityRealm="", nil

    if string.upper(mode)=="STANDALONE" then
        hostConf=string.format("%s/standalone/configuration/standalone.xml", homeDir)
    elseif string.upper(mode)=="DOMAIN" then
        hostConf=string.format("%s/domain/configuration/host.xml", homeDir)
    end

    debugPrint(string.format("getRealmName %s: %s", mode, hostConf))
    hostConfFile=io.open(hostConf)
    if hostConfFile then
        for line in hostConfFile:lines() do
            securityRealm=rex.match(line, [[security\-realm="(\w+)"]]) 
            if securityRealm then return securityRealm end
        end
    end

    if not securityRealm then return "ManagementRealm" end
end

function getAddress(runtimeCmd)
    local logFilePath=rex.match(runtimeCmd, [[-Dorg\.jboss\.boot\.log\.file=(\S*)]])
    local logFile=io.open(logFilePath)
    local address
    if logFile then
        for line in logFile:lines() do
            address=rex.match(line, [[Admin\sconsole\slistening\son\s(\S*)]])
            if address then return address end
        end
    end

    if not address then return "" end
end

function parseLastVersion(str)
    local res
    if string.upper(str)=="FINAL" then 
        res="1024"
    else 
        res=rex.match(str, [[\D*(\d+)]]) 
    end
    --print(string.format("parseLastVersion: %s, %s", res, str))

    return res
end

function verComp(ver, vulVer)
    print(tostring(ver), vulVer)
    local fVer, sVer, tVer, lVer=rex.match(ver, [[(\d+)\.(\d+)\.(\d+)\.(\S+)]])
    local fVulVer, sVulVer, tVulVer, lVulVer=rex.match(vulVer, [[(\d+)\.(\d+)\.(\d+)\.(\S+)]])

    if tonumber(fVer)<tonumber(fVulVer) then return nil end
    if tonumber(sVer)<tonumber(sVulVer) then return nil end
    if tonumber(tVer)<tonumber(tVulVer) then return nil end

    lVer=parseLastVersion(lVer)
    lVulVer=parseLastVersion(lVulVer)
    if tonumber(lVer)<tonumber(lVulVer) then return nil end
    
    return 1
end

function check4Vul(version)
    local CVE20155188="2.0.0.CR9"
    local CVE20155220="2.0.0.CR9"
    
    local cveDB={}
    if not version or version == "" then
        cveDB['20155188'] = 0
        cveDB['20155220'] = 0
        return cveDB
    end
    if not verComp(version, CVE20155188) then
        cveDB['20155188']=1
    else
        cveDB['20155188']=0
    end

    if not verComp(version, CVE20155188) then
        cveDB['20155220']=1
    else
        cveDB['20155220']=0
    end

    return cveDB
end

function start_check()
    local jbossDB, infoStr=handlePs()
    if not jbossDB then
        return 1,tostring(infoStr) --! No instance of jboss exists
    end
    jbossDB.pwdConf=pwdConf(jbossDB.homeDir)
    jbossDB.version=handleVersion(jbossDB.mode, jbossDB.homeDir)
    jbossDB.realmName=getRealmName(jbossDB.mode, jbossDB.homeDir)
    jbossDB.address=getAddress(jbossDB.runtimeCmd)
    jbossDB.cveDB=check4Vul(jbossDB.version)

    local tmpStr=string.format("%s/%s/%s", jbossDB.homeDir, string.lower(jbossDB.mode), "configuration/mgmt-users.properties")
    
    jbossDB.accounts=check_pwd(string.format("%s/%s/%s", jbossDB.homeDir, string.lower(jbossDB.mode), "configuration/mgmt-users.properties"), jbossDB.realmName)

    jbossDB.PID = nil
    jbossDB.realmName = nil
    jbossDB.baseDir = nil

    agent.lua_print_r(jbossDB)
    return 0,cjson.encode(jbossDB)
end

local tmp_code, tmp_msg
local msg_str = ""
local host = agent.get_erlang_data_server_host()
if string.sub(host, -1, -1) ~= "/" then
    host = host.."/"
end
local url = host.."api/v1/data_collection"
for _,one_cmd in pairs(json_tb.args.args) do
    local cmd = ""
    if one_cmd.name == "jboss_check" then
        tmp_code, tmp_msg = start_check()
    end
    if tmp_code ~= 0 then
        msg_str = msg_str.." execute "..one_cmd.name.." error: "..tostring(tmp_code).." "..
            tostring(tmp_msg)
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(tmp_msg)}
        if debug_on then
            agent.lua_print_r(data)
            --print(agent.base64_decode(data.result))
        end
        local j_str = cjson.encode(data)
        local is_compress = true
        tmp_code, http_code, tmp_msg = agent.post_json_to_srv(url, j_str, is_compress)
        if tmp_code ~= 0 and http_code ~= 200 then
            msg_str = msg_str.." post json to server error: "..tostring(tmp_code).." "..
                tostring(http_code).." "..tostring(tmp_msg)
        end
    else
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(tmp_msg)}
        if debug_on then
            agent.lua_print_r(data)
            --print(agent.base64_decode(data.result))
        end
        local j_str = cjson.encode(data)
        local is_compress = true
        tmp_code, http_code, tmp_msg = agent.post_json_to_srv(url, j_str, is_compress)
        if tmp_code ~= 0 and http_code ~= 200 then
            msg_str = msg_str.." post json to server error: "..tostring(tmp_code).." "..
                tostring(http_code).." "..tostring(tmp_msg)
        end
    end
end

local ret = {}
ret.ret_code = tmp_code
ret.ret_msg = msg_str
ret.req_id = json_tb.req_id
ret.begin_time = begin_time
ret.end_time = os.time()
cjson.encode_empty_table_as_object(false)
local json_rt = cjson.encode(ret)
if debug_on then
    agent.lua_print_r(ret)
else
    agent.sendmsg(tostring(json_tb.from), tostring(json_tb.type), "0xFF000000" , json_rt)
end
