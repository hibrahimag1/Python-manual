'''
Ovaj file sluzi kao skriptica za upoznavanje sa Python jezikom i sintaksom.
Svrha joj je da uštedite vrijeme upoznavajući se sa jezikom, jer vecina online
tutorijala ce vas pokusati nauciti i logiku programiranja (koju ste vec savladali u C/C++)

File je zamisljen kao interaktivno učenje.
Pokrenite ovaj file i pratite upute kroz terminal, a ujedno gledajte i napisani kod. Ako u bilo kojem
momentu zelite nesto provjeriti otvorite novi terminal i testirajte. Kada vidite na ekranu <enter>
pritisnite enter tek kad procitate tekst i kod koji slijedi i vidite novu print() liniju.


----- Osnove Python-a -----
Kao sto vidite vec smo iskoristili komentare, u Pythonu se komentari pisu na 2 nacina:
1. jednolinijski komentari pomocu #; isto kao // u C++
2. viselinijski komentari pomocu 3 znaka navodnika na pocetku i kraju komentara
(kao /* */ u C-u)

'''
# primjer jednolinijskog komentara

'''
Svaki novi jezik se uci prvo sa Hello World programom. Za razliku od mnogih drugih
jezika, python ne zahtijeva nikakav "boilerplate code".
Na primjer kod u C++ poput sljedeceg
#include <iostream>
int main(){
    std::cout << "Hello World" << std::endl;
    return 0;
}
u Pythonu je samo 1 linija koda:
'''

print("Hello World")
input("Pritisnite <enter>") # ignorirajte ovo za sad

''' 
Iza naredbi ne pišemo ";" kao u C/C++
naredba print() prima 1 parametar, string literal koji se treba ispisati, poput "Hello World"
ili neka varijabla (ne samo string). print() automatski ispisuje
i novi red na ekran, tj print("Hello World") u pythonu je isto kao i cout << "Hello World\n"; u C++.
Ako to ne želimo možemo "dodati" parametar end, koji mijenja znak koji se ispisuje poslije stringa
'''
print("Evo opet", end=" ")
print("ja", end=".")
input("<enter>")

''' 
Nakon ispisa valjalo bi spomenuti i unos medutim prvo moramo spomenut varijable u Pythonu.
Varijable se deklarišu na sljedeci nacin u Pythonu
var_name = value
To je to, nema potrebe za deklaracijom tipa, velicine, nista. Samo ime varijable i sta treba da cuva
Python automatski odreduje kojeg ce tipa biti varijabla na osnovu vrijednosti s desne strane znaka '='
'''
a = 5           # isto kao int a = 5;
b = 2.5252      # isto kao double b = 2.5252
c = "Cevapi"    # isto kao std::string c = "Cevapi";
d = True        # isto kao bool d = true;
'''
bool vrijednosti u Pythonu su True i False (obavezno prvo slovo veliko). Sve sto vrijedi
za bool-ove u C++ vrijedi i ovdje. Pri ispisu je razlika jer u C++ moramo poslat manipulator
boolalpha na izlazni tok, a u Pythonu se automatski ispisuju kao True/False. Aritmetika sa 
bool-ovima je ista, 5*True + 3 + 2*False će dati rezultat 8

print(var) je moguce, i to ce isprintati vrijednost objekta, kakva god bila, pa cak i ako one same 
sadrze vise elemenata (vidjecemo kasnije kako)
print(a,b,c,d) je moguce, tj u print-u se mogu nalaziti vise varijabli razlicitih tipova,
ne samo string, i izmedu njih ce se ispisati jedan razmak " ", a tek nakon zadnje varijable
se ispise string specificiran u end parametru (novi red po defaultu)
'''
print(a,b,c,d)
input("<enter>")

'''
Primijetite da se ovdje ne mogu desiti greske/konverzije tipa da bool varijabli dadnemo vrijednost 5
ili da int varijabli dadnemo vrijednost 4.55 pri *deklaraciji*. Ovo je zbog toga sto se tip
varijable odreduje na osnovu vrijednosti s desne strane. Zbog ovog razloga ne mozemo deklarisati
neinicijaliziranu varijablu u Pythonu, tj svaka varijabla mora imati neku vrijednost, makar 
vrijednost samog tipa (a = int ili s = str)

Tip varijable mozemo u kodu saznati pozivajuci type() funkciju koja vraca tip varijable ili literala
kojeg saljemo kao parametar. Neki od osnovnih tipova u Pythonu su int, float i str.
int predstavlja sve cjelobrojne vrijednosti, float sve decimalne, a str znakovne vrijednosti.
Sto se tice raspona ovih tipova, njihov raspon je vaša memorija na racunaru. Ne sikirajte se.

Jos da napomenemo da se tip podatka koji varijabla cuva moze mijenjati kroz program. To znaci da
ako smo deklarisali a = 5, mozemo kasnije u kodu dodijeliti joj vrijednost 5.5 ili vrijednost True,
vrijednost "Cuj moze i ovo" ili bilo sta validno.
'''
print(a, type(a))
a = 5.5555
print(a, type(a))
print(type("Pazi ovo"), type("Mislim da je ovo string")==str) # provjera tipa varijable
a = 10000000000000000000000000000000000000000000000000000000000000000
print(a // 1_000_000_000) # moguce je cifre unutar broja razdvajati sa _ radi preglednosti

input("<enter>")

'''
Kratki osvrt na matematicke operatore, moze: +, -, *, /, //, %, +=, -=, *=, /=, //=
U pythonu nema ++ i -- inc/decremenata.
/ je decimalno dijeljenje, // je cjelobrojno dijeljenje 5/2 je 2.5, 5//2 je 2.
** je operator stepenovanja, 2**3 je 8 u C++ bi morali koristiti pow ili rucno 2*2*2

Unos podataka sa ekrana se vrsi pomocu input() funkcije, koja nema obaveznih parametara,
ali moze primiti string literal ili varijablu (ne mora biti string, ali je konfuzno ako nije)
čija ce se vrijednost ispisati na ekran prije unosa.
sljedeca linija koda je slicna C++ kodu:
std::cout << "Unesite sta hocete: ";
std::cin >> unos;

Mozemo i samo pozvat input() bez dodjeljivanja njenog rezultata nekoj varijabli, kao sto
smo radili dosad u kodu s ciljem zaustavljanja toka programa sto bi se u C-u radilo pomocu
getchar() funkcije. Ono sto eventualno upisemo tad nece biti sacuvano nigdje.
'''
unos = input("Unesite sta hocete: ")
input("<enter>")

#Razmislite sta bi mogao sljedeci kod da ispise na ekran
print("Unijeli ste", unos, "i to je tipa", type(unos))
input("<enter>")
'''
Odgovor je da je unos varijabla tipa string. To je bilo nuzno da bi se moglo primiti bilo kakav
podatak, tako da nevezano jeste li upisali broj 5 ili tekst "Necu nista upisat" ono biva sacuvano
kao string u varijablu unos. Usput smo vidjeli kako mozemo ispisati formatirani ispis podataka:
print funkcija iz linije 114 bi se ekvivalentirala sljedecim C++ kodom
std::cout << "Unijeli ste" << " " << unos << " " << "i to je tipa" << " " << tip_unosa;
uz pretpostavku da je u varijabli tip_unosa sacuvan string "str" (jer nema type() funk u C++)
Dodatne " " sam stavio da naglasim pravilo print funkcije koje smo vec naveli da se argumenti
koji se navode ispisuju sa razmakom jedan izmedu drugog, osim zadnjeg nakon kojeg ide end string (default \n)

Ako smo sigurni da ce uneseni podatak bit broj mozemo izvrsiti eksplicitnu konverziju slicno kao u C++
'''
try:
    unos = int(input("Unesi neki cijeli broj: "))
    print(unos, "+ 5 = ", unos + 5)
except ValueError:
    print("Nemoj bit taki")
try:
    unos = float(input("Unesi neki decimalni broj: "))
    print(unos, "+ 0.25 = ", unos+0.25)
except ValueError:
    print("E jesi šašav")
input("<enter>")
'''
Uveli smo ovdje i try-except blok koji ima istu svrhu kao i try-catch blok u C++ i sluzi
za upravljanjem izuzetaka i grešaka. Ako unesemo neke rijeci poput "necu" ili "123xy"
int() konverzija ce baciti (throw) ValueError (slicno standardnim izuzecima logic_error i drugima)
koju hvatamo u except ValueError bloku i tu izvrsavamo odredene naredbe.
'''

'''
Vrijeme je da naučimo da kako se blokovi komandi pišu u Pythonu. U C/C++ koristimo ; i {} kada hocemo
da oznacimo kraj 1 naredbe, tj skupinu vise naredbi. U pythonu se ne koriste ; niti se koriste {} (u tu svrhu)
Isto tako u C/C++ postoje razni stilovi pisanja, gdje neko pise {} sa razmakom, neko u novi red prebacuje, neko
uvlaci sa 2 space-a, neko sa tab-om i slicno. U Pythonu su sve ove stvari riješene obaveznom indentacijom, tj 
uvlacenjem.
Svaka naredba ima svoju liniju koda i zbog toga ne zahtijeva ; da se oznaci kraj reda
A svaki blok naredbi se nalazi u istoj vertikalnoj liniji koda. Uvlacenje se vrsi tasterom TAB.
za koristenje petlji ili uslova u C/C++ se koristi {} a u Pythonu se koristi : (dvotacka)
'''
if (1 > 0): # kao da se ovdje nalazi {
    print("Ovo je pocetak bloka naredbi")
    print("Ovo je sredina")
    print("Ovo je kraj") # a ovdje }

print("Ovo je van bloka naredbi vezane za if uslov")

#while petlje se pisu na slican nacin kao u C/C++
i = 0
print("While petlja je ispisala: ", end="")
while (i<3):
    print(i, end=" ")
    i+=1
'''
for petlje su malo drugačije no logika je ista. 
U C++ bismo pisali
for (int i = 0; i<10; i++){
    std::cout << i << " ";
}
a u Pythonu pisemo:
'''
print("\nFor petlja je ispisala: ", end="")
for i in range(10):
    print(i, end=" ")
input("<enter>")

'''
range() moze raditi na vise nacina:
1. range(x) - dadne raspon [0, x)
2. range(x, y) - dadne raspon [x, y)
3. range(x,y,z) - dadne raspon pocevsi od x-a, s korakom z, dok ne sustigne ili prede vrijednost y

i je privremena varijabla koja zivi samo dok je for petlja aktivna
'''
for i in range(5):
    print(i, end=" ")
print() # za ispisivanje novog reda isto kao i print("\n") ili cout << endl
for i in range(5, 10):
    print(i, end=" ")
print("\nParni elementi izmedu 1 i 10 su: ")
for i in range(2, 10, 2): # da sam stavio 1,10,2 ispisalo bi 1,3,5,7,9
    print(i, end=" ")
input("\n<enter>")

'''
for i in range(x) je specijalni slucaj opcenite for petlje koja je identicna rasponskoj for petlji iz C++
U C++ ona glasi: 
for (tip var : neka_kolekcija){
    tijelo_petlje
}
U Pythonu je to: 
for var in neka_kolekcija:
    tijelo_petlje

range(x) stvara instancu range klase koja je ustvari jedan objekat slican nekoj kolekciji (iterable),
tj sadrzi elemente kroz koje mozemo prolaziti. Nasa i varijabla poprima vrijednosti tih elemenata u 
svakoj iteraciji petlje. Naravno ako je kolekcija prazna (nema elemenata) for petlja se nece ni odradit.
'''
for i in {1,2,3}: # kolekcija o kojoj cemo uskoro pricati
    print(i, end=" ")
input("<enter>")
'''
Funkcije u Pythonu sluze istoj svrsi kao i funkcije u C/C++. Deklariraju se na sljedeci nacin:
def func_name(param1, param2...):
    skup_naredbi
    return value

def je kljucna rijec koja je obavezna kad deklarisemo funkcije, funkcija moze da ima parametara, 
a i ne mora. Parametrima ne navodimo tipove vec samo imena. Iz funkcije mozemo a i ne moramo vratit
vrijednost, s tim sto ako pokusamo ispisati vrijednost funkcije koja ne vraca nista dobicemo None. (kao NULL u C++)
Moze se slat parametar kakav hocete, i vratit sta hocete. Naravno samo 1
stvar se moze vratit, ne vise njih. Unutar funkcija se mogu deklarisati nove funkcije, te funkcije postoje samo unutar
funckije pod kojom su definisane. Parametri mogu imati default vrijednost, sto znaci da ih ne moramo
navoditi kad ih pozivamo i funkcija ce raditi kako treba. Ovo smo vec vidjeli
u print funkciji sa njenim parametrom end, koja ima default vrijednost "\n".
Ako bas zelimo naglasiti tipove parametara koje ocekujemo (samo naglasavmo, ne forsiramo) mozemo uraditi sljedece:
def func(x: int, y:str,...) Ako ubacimo recimo string na mjestu parametra koji se koristi kao int u funkciji, 
dobicemo TypeError. 
'''
def suma(x: int, y=2):
    return x+y

def suma2(x: int, y:int):
    def suma(x, y):
        return 2*(x+y)
    return suma(x,y)

print(suma(5,10), suma(5), suma2(5,10))

input("<enter>")
'''
Sada cemo spomenuti neke strukture podataka. Prvu koju cemo spomenuti, koja se najvise koristi je list
list je spoj C-ovskog niza i C++ vektora, jer se pise kao niz ali ima funkcionalnost kao vektor (i vise)
'''
l = [1,2,3,4] # deklaracija liste l
'''
Liste podrzavaju mnogo stvari:
- listama ne deklariramo velicinu kao kod nizova l[3] = {1,2,3} ili vektora vector<int, 3>. Oni automatski
odreduju svoju velicinu na osnovu izraza sa desne strane, kao i bilo koji drugi tip podatka. Ako hocemo praznu
listu napisemo l = []
- indeksiranje clanova je identicno kao kod obicnih nizova. Indeks pocinje od 0, a ako pokusamo pristupiti
indeksu clana koji ne postoji dobijamo IndexError (npr. l[10])
- elemente dodajemo u listu pomocu append() funkcije koju pozivamo nad instancom liste (varijablom liste), isto
kao sto to radimo s vektorima pomocu vector.push_back()
- elemente brisemo pomocu .remove() (napomena: ako stavim .ime_funk() to znaci da se funkcija poziva nad objektom)
npr l.remove(2) ce izbrisati ELEMENT 2 a ne element pod indeksom 2. Ako navedeni element nije u listi npr 
l.remove(420) dobivamo ValueError. 
- Ako zelimo izbaciti element pod odredenim indeksom koristimo .pop() gdje upisujemo cjelobrojni validni indeks
(inace TypeError l.pop(2.5) ili IndexError l.pop(500)). npr l.pop(0) ce izbaciti prvi element (u ovom slucaju 1)
ili mozemo koristiti del l[0]
- Elementima se moze pristupiti od kraja, npr l[-1] ce dati zadnji element (prvi od zada), l[-2] predzadnji elem
(drugi od zada) i slicno.
- Ako neki element zelimo ubaciti na odredeni indeks to radimo pomocu .insert() ciji je prvi parametar indeks na
koji ubacujemo, a drugi parametar objekat (literal ili varijabla) koji ubacujemo.
- Liste mogu cuvati razlicite tipove podataka istovremeno sto znaci da nesto poput
l = [1, True, "cak i string sine", -5.2525] je sasvim legalno (ne nuzno i preporucljivo).
- Moze se koristiti nesto sto se zove "slicing", a to je ustvari da dobijemo sublistu nase liste. Koristi se pomocu
dvotacke unutar []. Npr l[a:b] ce dati elemente liste l na indeksima [a,b). Istrazite ovo sami
To je to sto mi moze past na pamet trenutno, od osnovnih stvari
'''
print("Treci element je:", l[2])
l.append(15)
print("Zadnji element je:", l[-1])
l.remove(1)
l.insert(0, "Nisi ovo ocekivao a")
print(l)
l.pop() # ako ne navedemo indeks podrazumijeva se zadnji
print(l[:-1]) # printaj sve osim zadnjeg
input("<enter>")

'''
Ukratko cemo spomenuti i jos neke. 
String radi na iste nacine kao i string u C++, s tim sto se u pythonu mogu stringovi direktno indeksirat,
i radi slicing i sa njima. Stringovi su immutable, sto znaci da se ne mogu mijenjat, tj 
s = "abcdef"
s[2] = C
nece raditi, ako bismo takav efekat htjeli postici morali bismo napraviti potpuno novi string
stringovi se mogu navoditi i sa duplim i sa jednostrukim navodnicima, nema razlike kao u C-u
char u C/C++ je samo string duzine 1 u pythonu.
Za vise o stringovima pogledajte: https://www.w3schools.com/python/python_strings.asp

Set je tip podataka koji ne sadrzi duplikate i nije poredan.
To znaci da ne znamo kako ce izgledati raspored elemenata kad ga isprintamo, samim time ne
moze se indeksirati. Moze sadrzavati samo unikatne elemente. Korisne funkcije .remove, .add, 
.union, .update, len(). True i 1, odnosno False i 0 se smatraju duplikatima
Deklarira se na dva nacina
1 - viticastim zagradama my_set = {1,2,3}
2 - konverzijom set([1,2,3])

Dictionary je tip podataka koji sadrzi key-value parove, bas kao sto i pravi rjecnik
ima parove termina i njihovih definicija. I za njega se koriste {}
dct = {key1: value1, key2:value2, key3:value3}
kljucevi mogu biti tipovi poput int i string, dok vrijednosti mogu biti sta bilo.
Vrijednostima pristupamo preko kljuca dct[key1] ce nam dati value1 (ako ne postoji KeyError).
Mozemo i preko dct.get(key1, def) koja ce nam vratiti value1 ako postoji key1, a
neku default value def ako ne postoji. 
'''

'''
Od velikog znacaja za zadacu iz VIS-a je i poznavanje rada sa bibliotekama
U python file se ukljucuje druga biblioteka (module) na 2 nacina:
1. import lib_name
2. from lib_name import nesto
s tim sto nesto moze biti funkcija, objekat, klasa i slicno.
Ako zelimo koristiti npr funkciju iz biblioteke onda je pozivamo ovako: lib_name.func()
'''
import math
print(math.sqrt(5))
'''
Ili ako smo uvezli samo sqrt funkciju pomocu from math import sqrt, onda mozemo pisati
print(sqrt(5)). Pri tome, ako smo ovako uvezli samo funkciju ne mozemo koristiti math.sqrt() vec samo sqrt()
Opcionalno se moze dodat keyword as, sto radi slicno kao typedef, dajuci alias (drugo ime) onome
ispred cega se pise, tako se cesto pise
import numpy as np
import pandas as pd
ili 
from turtle import Turtle as t

ako i mi deklariramo neku funkciju koja se zove isto kao funkcija iz neke biblioteke, redeklarisali smo
funkciju, to jest, funkcija iz biblioteke (ako je ona uvezena prije deklaracije nase funkcije) ce bit izgubljena
'''

'''
Na kraju cu spomenut neke zanimljive stvari

Formatirani ispis u pythonu ima vise nacina, ali najnoviji i najbolji je f-string (formatted-string)
Ispred znaka navodnika za pocetak stringa pisemo malo slovo f, a onda unutar string kad god zelimo
da na nekom mjestu upisemo neku varijablu ili izraz koji se treba izracunati stavimo unutar {}.

Isto tako ako hocemo pisati ' u stringu onda mozemo navesti string pomocu ", ili obrnuto. Escape
char je \.
'''
input("<enter>")
print(f"Ja mislim da je 3+5 = {3+5}")
print("Ja bih da napisem apostrof k'o covjek")
print('A ja bih ipak da citiram nekog covjeka: "Recimo bas ovako"')
print("\"Al ne mogu k'o čovjek da citiram\", vele oni meni tako")
print()

#Zanimljiva je funkcija exec, koja ce pokusati izvrsiti ono sto joj se navede. Naprimjer
prog = 'print("Ovo je zadnji print")'
exec(prog)
'''
Ovo vam govorim iz razloga jer vam moze neko poslat python file u kojem ima ova naredba pomocu koje
vam vrlo lahko moze izbrisat operativni sistem ili nesto a da ni ne posumnjate. Na primjer ovaj file :)
Naredbe tipa exec(input()) strogo izbjegavati
'''
'''
Isto tako stringovi od vise istih karaktera se mogu napraviti slicno kao u C++
s = "*"*5 ce dati string "*****"

Ne postoje pokazivaci u pythonu, a ni ne trebaju vam

Datoteke se otvaraju u pythonu na sljedeci nacin
with (file_path: str, open_mode: str) as var:
    radi_nesto

cim se zavrsi blok naredbi file se automatski zatvara i ne mozemo mu vise pristupiti. open_mode parametar
moze biti "w", "r", "a", sto su nacini otvaranja/azuriranja datoteke, isto kao i u C/C++

U pythonu se mogu pisati ; na kraju naredbi i ako nekad htjednete napisati 2 naredbe u jednoj liniji, moze vam pomoci
i = 0
while (i<5):
    print(i); i+=1
Ali je ovo jako "unpythonic" tj nije u duhu pythona
'''

'''
To bi bilo to za ovu skripticu, naravno ni blizu nije sve spomenuto i objašnjeno, ali to nije bio ni cilj
Nadam se da necete imati problema pisati jednostavnije python programe i da vam je ova skripta bila od pomoci.
Za bilo kakve greske ili dodatke posaljite mi mail ili commit-ajte na githubu
Sretno!


Napisao: Harun Ibrahimagić 
16.3.2024. 
email: hibrahimag1@etf.unsa.ba
'''