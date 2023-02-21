

pub struct BigNum(String);

impl BigNum {
    pub fn new(num: &str) -> Self {
        BigNum(String::from(num))
    }

    pub fn to_string(&self) -> String {
        self.0.clone()
    }

    /// Returns an String containing the Integer part. Doesn't change the object state.
    pub fn truncate(&self) -> String {
        let ret : Vec<&str> = self.0.split('.').collect();

        if let Some(value) = ret.get(0) {
            return value.to_string();
        }
        return self.0.clone();
    }

    pub fn convert_binary_to_hex(binary: &String) -> String {
        assert!(binary.len() % 4 == 0);

        let to_hex = |x: &str| {
            match x {
                "0000" => "0",
                "0001" => "1",
                "0010" => "2",
                "0011" => "3",
                "0100" => "4",
                "0101" => "5",
                "0110" => "6",
                "0111" => "7",
                "1000" => "8",
                "1001" => "9",
                "1010" => "A",
                "1011" => "B",
                "1100" => "C",
                "1101" => "D",
                "1110" => "E",
                "1111" => "F",
                _ => "error"
            }
        };

        let mut ret = String::new();
        for w in (0..binary.len()).step_by(4) {
            let binary_chunk = &binary.as_str()[w..w+4];
            let hex = to_hex(binary_chunk);
            ret += hex;
        }

        return ret;

    }

    pub fn calc_magic_constants(w: u32) {
        // Value of 'e' extracted from https://www.math.utah.edu/~pa/math/e.html
        // We need a high resolution float in order to properly calculate the magic constant
        let mut euler_minus_2 = BigNum::new("0.7182818284590452353602874713526624977572470936999595749669676277240766303535475945713821785251664274274663919320030599218174135966290435729003342952605956307381323286279434907632338298807531952510190115738341879307021540891499348841675092447614606680822648001684774118537423454424371075390777449920695517027618386062613313845830007520449338265602976067371132007093287091274437470472306969772093101416928368190255151086574637721112523897844250569536967707854499699679468644549059879316368892300987931277361782154249992295763514822082698951936680331825288693984964651058209392398294887933203625094431173012381970684161403970198376793206832823764648042953118023287825098194558153017567173613320698112509961818815930416903515988885193458072738667385894228792284998920868058257492796104841984443634632449684875602336248270419786232090021609");
        
        for _ in 0..w {
            euler_minus_2.multiply(2);
        }
        
        let a = euler_minus_2.truncate();
        let mut a = BigNum::convert_to_binary(&a);
        BigNum::binary_odd(&mut a); // I'd better use mut reference 
        let a = BigNum::convert_binary_to_hex(&a);
        
        println!("P{} -> {:?}", w, a);

        // Value of golden ration from http://www2.cs.arizona.edu/icon/oddsends/phi.htm
        let mut golden_ratio_minus_1 = BigNum::new("0.6180339887498948482045868343656381177203091798057628621354486227052604628189024497072072041893911374847540880753868917521266338622235369317931800607667263544333890865959395829056383226613199282902678806752087668925017116962070322210432162695486262963136144381497587012203408058879544547492461856953648644492410443207713449470495658467885098743394422125448770664780915884607499887124007652170575179788341662562494075890697040002812104276217711177780531531714101170466659914669798731761356006708748071013179523689427521948435305678300228785699782977834784587822891109762500302696156170025046433824377648610283831268330372429267526311653392473167111211588186385133162038400522216579128667529465490681131715993432359734949850904094762132229810172610705961164562990981629055520852479035240602017279974717534277759277862561943208275051312181562");
        for _ in 0..w {
            golden_ratio_minus_1.multiply(2);
        }
        
        let a = golden_ratio_minus_1.truncate();
        let mut a = BigNum::convert_to_binary(&a);
        BigNum::binary_odd(&mut a); // I'd better use mut reference 
        let a = BigNum::convert_binary_to_hex(&a);
        
        println!("Q{} -> {:?}", w, a);
        println!("")

    }

    pub fn convert_to_binary(decimal : &String) -> String {
        // https://stackoverflow.com/questions/11006844/convert-a-very-large-number-from-decimal-string-to-binary-representation
        
        let odds_to_one = |v :&String| -> u8 {

            if v.ends_with("1") |
                v.ends_with("3") |
                v.ends_with("5") |
                v.ends_with("7") |
                v.ends_with("9") {
                return 1_u8;
            }
            else {
                return 0_u8;
            }
        };
        
        let div_by_two = |s: &String| -> String {
            let mut new_s = "".to_string();
            let mut add = 0;

            for ch in s.as_bytes() {
                let new_dgt = ((ch - '0' as u8) / 2 as u8) + add;
                new_s = format!("{}{}", new_s, new_dgt);
                add = odds_to_one(&format!("{}", ch)) * 5;
            }

            if new_s != "0" && new_s.starts_with('0') {
                new_s = String::from(&new_s[1..]);
            }

            new_s
        };

        if decimal == "0" {
            return "0".to_string();
        }
        else {
            let mut ret = "".to_string();
            let mut d = decimal.clone();
            while d != "0" {
                ret = format!("{}{}", odds_to_one(&d), ret);
                d = div_by_two (&d);
            }

            return ret.to_string();
        }
    }

    /// For a binary input this just forces the number to be odd
    /// The input is a String that contains a sequence of 1's and 0's.
    pub fn binary_odd(binary: &mut String) {
        let len = binary.len();
        if binary.len() > 0 {
            binary.replace_range(len -1..len, "1");
        }
    }

    pub fn multiply(&mut  self, num2: u128) {

        let num1: Vec<char> = self.0.chars().collect();
        let num2: Vec<char> = num2.to_string().chars().collect();

        let num1 = num1.iter().map(|c| *c as u8).collect::<Vec<u8>>();
        let num2 = num2.iter().map(|c| *c as u8).collect::<Vec<u8>>();

        let len1 = num1.len();
        let len2 = num2.len();

        if len1 == 0 || len2 == 0 {
            self.0 = "0".to_string();
            return;
        }

        let mut result = vec![0_u8; len1 + len2];

        let mut i_n1 = 0;
        let mut i_n2;

        let mut dot_index = 0;

        for i in (0..len1).rev() {
            if num1[i] == '.' as u8 {
                dot_index = len1 - i - 1;
                continue;
            }

            let mut carry =0;
            let n1 = num1[i] - '0' as u8;

            i_n2 = 0;

            for j in (0..len2).rev() {
                let n2 = num2[j] - '0' as u8;
                let partial_res = n1 * n2 + result[i_n1+i_n2] + carry;

                carry = partial_res/10;

                result[i_n1 + i_n2] = partial_res % 10;

                i_n2 += 1;
            }

            if carry > 0 {
                result[i_n1 + i_n2] += carry;
            }

            i_n1 += 1;
        }

        if dot_index != 0 {
            result.insert(dot_index, '.' as u8);
        }
        result.reverse();

        result = result.iter().map(|c| { if *c == '.' as u8 {return *c;} else {return *c + '0' as u8;} } ).collect();

        if let Some(first_pos) = result.iter().position(|c| *c != '0' as u8) {
            self.0 = String::from_utf8_lossy(&result[first_pos..]).to_string();
        }
        else {
            self.0 = "0".to_string();
        }
    }
}

pub fn div_ceil(numerator: usize, divisor: usize) -> usize {
    return (numerator + (divisor - 1)) / divisor;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_test() {
        let mut res = BigNum::new("123456789000000000000000000000000000000000000011111111111111111111111.0");
        res.multiply(20);
        let expected = "2469135780000000000000000000000000000000000000222222222222222222222220.0".to_string();
        assert_eq!(res.to_string(), expected);

        let mut res = BigNum::new("123456789000000000000000000000000000000000000011111111111111111111111");
        res.multiply(0);
        assert_eq!(res.to_string(), "0".to_string());
    }

    #[test]
    fn binary_odd_test() {
        let mut val = String::from("100");
        BigNum::binary_odd(&mut val);
        assert_eq!(val, "101".to_string());

        let mut val = String::from("11");
        BigNum::binary_odd(&mut val);
        assert_eq!(val, "11".to_string());
    }

    #[test]
    fn convert_to_binary_test() {
        assert_eq!("111", BigNum::convert_to_binary(&"7".to_string()));
    }

    #[test]
    fn binary_to_hex_test() {
        assert_eq!("F", BigNum::convert_binary_to_hex(&"1111".to_string()));
    }

    #[test]
    fn calc_magic_consts_test() {
        BigNum::calc_magic_constants(16);
        BigNum::calc_magic_constants(32);
        BigNum::calc_magic_constants(64);
        BigNum::calc_magic_constants(128);

        // We don't have primitive values to keet the next in a native way
        BigNum::calc_magic_constants(256);
        BigNum::calc_magic_constants(512);
    }

    #[test]
	fn div_ceil_test() {
		assert!(15 == div_ceil(59, 4));
		assert!(15 == div_ceil(15, 1));
		assert!(12 == div_ceil(23, 2));
		assert!(5 == div_ceil(17, 4));
	}

}

