// Vladimir Ovechkin 2022
// All Rights Reserved

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <inttypes.h>
#include <limits.h>

// An instruction is a bit string with 32 bits.
typedef uint32_t Instr;

// Length of a 32-bit integer as a binary string (+1 for
// null terminator)
#define BSTR_LEN 33

// Unsigned 32-bit integer to binary string.
static void u32_to_bstr(uint32_t num, char s_out[BSTR_LEN]) {
  for (uint32_t i = 0; i < 32; i++)
    s_out[i] = ((num >> (31 - i)) & 1) + '0';
  s_out[32] = '\0';
}

// Length of a 32-bit integer as a hex string (+1 for
// null terminator)
#define HSTR_LEN 5

// Unsigned 32-bit integer to hex string.
static void u32_to_hstr(uint32_t num, char s_out[HSTR_LEN]) {
  for (uint32_t i = 0; i < 8; i++) {
    // 1 nibble is 4 bits
    int nibble = (num >> ((7 - i) * 4)) & 0xF;
    s_out[i] = nibble + (nibble < 10 ? '0' : ('A' - 10));
  }
  s_out[8] = '\0';
}

typedef enum {
  DEC_IT = 10,
  BIN_IT = 2,
  HEX_IT = 16,
} IntType;

static bool is_digit(char c, IntType it) {
  switch (it) {
  case DEC_IT:
    return '0' <= c && c <= '9';
  case BIN_IT:
    return c == '0' || c == '1';
  case HEX_IT:
    return
      ('0' <= c && c <= '9') ||
      ('a' <= c && c <= 'f') ||
      ('A' <= c && c <= 'F');
  }
}

static int digit_to_int(char c, IntType it) {
  if ('0' <= c && c <= '9')
    return c - '0';

  if (it == HEX_IT)
    return c - ('a' <= c && c <= 'f' ? 'a' : 'A') + 10;

  return -1;
}

#define is_odd(e) ((e) & 1)
#define is_even(e) (!is_odd((e)))

static uint32_t rotate_right(uint32_t x, uint32_t n) {
  uint32_t mask = (CHAR_BIT * sizeof(n) - 1);
  n &= mask;
  return (x >> n) | (x << ((-n) & mask));
}

// Returns whether s starts with pre.
static bool str_starts_with(const char* s, const char* pre) {
  while (*pre != '\0')
    if (*(pre++) != *(s++))
      return false;
  return true;
}

static void print_s(const char* s, int idx, int len) {
  printf("%s\n%*s", s, idx, "");
  for (int i = 0; i < len; i++)
    putchar('^');
  putchar('\n');
}

static const char* literals[] = {
	// Data-processing instructions
	"AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC", "TST",
	"TEQ", "CMP", "CMN", "ORR", "MOV", "LSL", "LSR", "ASR", "RRX",
	"ROR", "BIC", "MVN",
	
	// Conditions
  "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL", "VS", "VC", "HI",
  "LS", "GE", "LT", "GT", "LE", "AL",

	// Misc.
	"PC", "LR", "S", "R", ",", "#"
};

static const int literals_size = sizeof(literals) / sizeof(*literals);

typedef enum {
  // Literal tokens that correspond to indices in `literals`.

	// Data-processing instructions
	AND_T, EOR_T, SUB_T, RSB_T, ADD_T, ADC_T, SBC_T, RSC_T, TST_T,
	TEQ_T, CMP_T, CMN_T, ORR_T, MOV_T, LSL_T, LSR_T, ASR_T, RRX_T,
	ROR_T, BIC_T, MVN_T,
	
	// Conditions
  EQ_T, NE_T, CS_T, HS_T, CC_T, LO_T, MI_T, PL_T, VS_T, VC_T, HI_T,
  LS_T, GE_T, LT_T, GT_T, LE_T, AL_T,

	// Misc.
	PC_T, LR_T, S_T, R_T, COMMA_T, HASH_T,

	// Non-literal tokens
  INT_T, UNK_T, EOL_T,
} TokenType;

typedef struct {
  TokenType type;
  int idx;
  int len;
  
  union {
    /* INT_T */ uint32_t val;
  };
} Token;

typedef struct {
  const char* s;
  int         idx;
  Token       peeked_token;
  bool        peeked_token_active;
} Scanner;

static void scanner_init(Scanner* scanner, const char* s) {
  scanner->s   = s;
  scanner->idx = 0;
}

static Token next_token(Scanner* scanner) {
  if (scanner->peeked_token_active) {
    scanner->peeked_token_active = false;
    return scanner->peeked_token;
  }
  
  const char* s = scanner->s;
  int idx       = scanner->idx;

  while (s[idx] == ' ') idx++;
  
  Token token;
  token.type = EOL_T;
  token.idx  = idx;
  
  int unknown_idx = -1;
  int unknown_len = 0;
  
  while (s[idx] != ' ' && s[idx] != '\0') {
    for (int i = 0; i < literals_size; i++)
      if (str_starts_with(s + idx, literals[i])) {
        token.type = i;
        token.len  = strlen(literals[i]);
        idx        += token.len;
        goto END;
      }

    if (is_digit(s[idx], DEC_IT)) {
        token.type = INT_T;
        token.len  = 0;
        token.val  = 0;

        int min_len = 0;
        
        IntType int_type = DEC_IT;
        if (s[idx] == '0') {
          if (s[idx + 1] == 'x')
            int_type = HEX_IT;
          else if (s[idx + 1] == 'b')
            int_type = BIN_IT;

          if (s[idx + 1] == 'x' ||
              s[idx + 1] == 'b' ||
              s[idx + 1] == 'd') {
            idx += 2;
            token.len += 2;
            min_len = 2;
          }
        }

        bool overflow = false;

        while (is_digit(s[idx], int_type)) {
          int digit = digit_to_int(s[idx], int_type);
          
          if (token.val > (UINT32_MAX - digit) / int_type)
            overflow = true;
          
          token.val = (token.val * int_type) + digit;
          token.len++;
          idx++;
        }

        if (overflow) {
          print_s(s, token.idx, token.len);
          printf("Integer '%.*s' is too large to parse, "
                 "max integer is %" PRIu32 ".\n",
                 token.len, s + token.idx, UINT32_MAX);
          exit(EXIT_FAILURE);
        }

        if (token.len <= min_len) {
          unknown_idx = unknown_idx == -1 ? idx : unknown_idx;
          unknown_len += token.len;
          continue;
        }

        goto END;
    }

    unknown_idx = unknown_idx == -1 ? idx : unknown_idx;
    unknown_len++;
    idx++;
  }

 END:
  if (unknown_idx != -1) {
    token.type = UNK_T;
    token.idx  = unknown_idx;
    token.len  = unknown_len;
  }
  
  scanner->idx = idx;
  return token;
}

static Token peek_token(Scanner* scanner) {
  Token token = next_token(scanner);
  scanner->peeked_token        = token;
  scanner->peeked_token_active = true;
  return token;
}

static const char* token_to_str(TokenType type) {
  if (type < literals_size)
    return literals[type];
  
  switch (type) {

  case INT_T:
    return "integer";
    
  case UNK_T:
    return "unknown token";

  case EOL_T:
    return "end of line";
    
  default:
    return NULL;
  }
}

static Token expect_token(Scanner* scanner, TokenType type) {
  Token token = next_token(scanner);

  if (token.type != type) {
    print_s(scanner->s, token.idx, token.len);
    printf("Error: expected '%s', got '%s'.\n",
           token_to_str(type), token_to_str(token.type));
    exit(EXIT_FAILURE);
  }

  return token;
}

typedef enum {
  EQ = 0b0000,
  NE = 0b0001,
  CS = 0b0010,
  CC = 0b0011,
  MI = 0b0100,
  PL = 0b0101,
  VS = 0b0110,
  VC = 0b0111,
  HI = 0b1000,
  LS = 0b1001,
  GE = 0b1010,
  LT = 0b1011,
  GT = 0b1100,
  LE = 0b1101,
  AL = 0b1110,
} Cond;

static bool token_to_cond(Token token, Cond* cond_out) {
  
#define handle(cond) case cond ## _T: *cond_out = cond; return true;
  
  switch (token.type) {
    handle(EQ);
    handle(NE);
  case HS_T:
    handle(CS);
  case LO_T:
    handle(CC);
    handle(MI);
    handle(PL);
    handle(VS);
    handle(VC);
    handle(HI);
    handle(LS);
    handle(GE);
    handle(LT);
    handle(GT);
    handle(LE);
    handle(AL);
  default:
    return false;
  }

#undef handle
}

static uint32_t token_to_cmd(Token token) {
  
#define handle(type, val) case type ## _T: return val;
  
  switch (token.type) {
    handle(AND, 0b0000);
    handle(EOR, 0b0001);
    handle(SUB, 0b0010);
    handle(RSB, 0b0011);
    handle(ADD, 0b0100);
    handle(ADC, 0b0101);
    handle(SBC, 0b0110);
    handle(RSC, 0b0111);
    handle(TST, 0b1000);
    handle(TEQ, 0b1001);
    handle(CMP, 0b1010);
    handle(CMN, 0b1011);
    handle(ORR, 0b1100);
  case MOV_T:
  case LSL_T:
  case ASR_T:
  case RRX_T:
    handle(ROR, 0b1101);
    handle(BIC, 0b1110);
    handle(MVN, 0b1111);
  default:
    return -1;
  }
  
#undef handle
}

// Cond is bits 31-28 and dictates under what condition instructions
// should execute under.
static Instr set_cond(Instr instr, Cond cond) {
  return instr | ((0xF & cond) << 28);
}

static Instr set_op(Instr instr, uint32_t op) {
  return instr | (op << 26);
}

static Instr set_I(Instr instr) {
  return instr | (1 << 25);
}

static Instr set_cmd(Instr instr, uint32_t cmd) {
	return instr | (cmd << 21);
}

// S bit is for data-processing instructions and is the 20th bit.
// It controls whether the instructions will set condition flags.
static Instr set_S(Instr instr) {
  return instr | (1 << 20);
}

// Rd is bits 12-15 that indicate the register for data processing and
// memory instructions. Assumes Rd is not already set.
static Instr set_Rd(Instr instr, uint32_t reg) {
  return instr | (reg << 12);
}

// Rn is bits 16-19 that indicate the register for data processing and
// memory instructions. Assumes Rn is not already set.
static Instr set_Rn(Instr instr, uint32_t reg) {
  return instr | (reg << 16);
}

static Instr set_shamt5(Instr instr, uint32_t shamt5) {
	return instr | (shamt5 << 7);
}

static Instr set_sh(Instr instr, uint32_t sh) {
	return instr | (sh << 5); 
}

static Instr set_Rm(Instr instr, uint32_t reg) {
	return instr | reg;
}

static Instr set_imm8m(Instr instr, uint32_t val, const char* s,
                       int idx, int len, const char* instr_name) {
  if (val <= 0xFF)
    return instr | val;
  
  int first = -1;
  int last  = -1;
  
  for (int i = 0; i < 32; i++) {
    bool bit = (val >> i) & 1;
    
    if (bit) {
      if (first == -1)
        first = i;
      else if (last == -1)
        last = i;
    }
  }

  if (last == -1 && first == -1)
    return instr;

  if (last == -1)
    last  = first;
  if (first == -1)
    first = 0;

  int width = last - first + 1;
  if (width > 16) {
    width = 34 - width;
    
    int temp = last;
    last = first;
    first = temp;
  }
  
  if (width > 8) {
    char val_bstr[BSTR_LEN];
    u32_to_bstr(val, val_bstr);
    
    print_s(s, idx, len);
    printf("Invalid immediate. More details below:\n\n"
           "For data-processing instructions such as %s, immediates\n"
           "in the 3rd operand are encoded using 12 bits: an 8 bit\n"
           "value and 4 bit rotation amount.\n\n"
           "The immediate %" PRIu32 " given has a distance of %d\n"
           "between its least significant one at position %d and\n"
           "most significant one at position %d (see the binary\n"
           "representation of the immediate below). This is too\n"
           "large to fit into 8 bits, and thus cannot be encoded.\n\n"
           "Binary representation of %" PRIu32 ":\n%s\n\n",
           instr_name, val, width, first, last, val, val_bstr);
    exit(EXIT_FAILURE);
  }

  last = (first + 7) % 32;

  uint32_t rotation, bottom;
  
  for (int i = 0; i <= 8 - width; i++) {
    rotation = last < 8 ? (7 - last) : (7 + 32 - last);
    bottom   = rotate_right(val, 32 - rotation);

    if (is_even(rotation) && rotation <= 30)
      return instr | (rotation / 2 << 8) | bottom;

    last  = (last - 1 + 32) % 32;
    first = (first - 1 + 32) % 32;
  }

  // There are a few special cases when width = 8
  // that cannot be rotated by an even number to
  // equal val. For width < 8, you can always
  // "shift by an odd amount" by padding the left
  // or right of bottom with 0s.
  char val_bstr[BSTR_LEN];
  u32_to_bstr(val, val_bstr);

  char bottom_bstr[BSTR_LEN];
  u32_to_bstr(bottom, bottom_bstr);
    
  print_s(s, idx, len);
  printf("Invalid immediate. More details below:\n\n"
         "For data-processing instructions such as %s, immediates\n"
         "in the 3rd operand are encoded using 12 bits: an 8 bit\n"
         "value and 4 bit rotation amount.\n\n"
         "The immediate %" PRIu32 " given has an 8 bit base value\n"
         "of 0b%s that must be rotated right %" PRIu32 " times to\n"
         "form the immediate (see binary representation below).\n"
         "The issue is that the 4 bit value is encoded as\n"
         "rotation / 2, and the rotation in this case is not even,\n"
         "so this immediate is impossible to encode.\n\n"
         "Binary representation of %" PRIu32 ":\n%s\n\n",
         instr_name, val, bottom_bstr + 24, rotation, val, val_bstr);
  printf("FAIL\n");
  exit(EXIT_FAILURE);
}

static int parse_reg(Scanner* scanner) {
  Token token = peek_token(scanner);
  if (token.type == PC_T) {
    token.val = 15;
		token = next_token(scanner);
  } else if (token.type == LR_T) {
    token.val = 14;
		token = next_token(scanner);
  } else {
    token = expect_token(scanner, R_T);
    token = expect_token(scanner, INT_T);
  }

  if (token.val > 15) {
    print_s(scanner->s, token.idx - 1, token.len + 1);
    printf("Error: expected R0-R15, LR, or PC, got R%" PRIu32 ".\n",
           token.val);
    exit(EXIT_FAILURE);
  }

  return token.val;
}

static Instr parse_data_Src2(Scanner* scanner, Instr instr,
                             const char* instr_name) {
  Token token = peek_token(scanner);
  
  if (token.type == HASH_T) {
    token = next_token(scanner);
    token = expect_token(scanner, INT_T);
    instr = set_imm8m(instr, token.val, scanner->s, token.idx,
                      token.len, instr_name);
    instr = set_I(instr);
		
  } else if (token.type == R_T) {
		uint32_t reg    = parse_reg(scanner);
		uint32_t shamt5 = 0;
		uint32_t sh     = 0;
		TokenType shift_type = token.type;

		token = peek_token(scanner);

		printf("%s\n", token_to_str(token.type));
		
		switch (token.type) {
		case LSL_T:
			token = next_token(scanner);
			break;
			
		case LSR_T:
			sh = 0b01;
			token = next_token(scanner);
			break;
			
		case ASR_T:
			sh = 0b10;
			token = next_token(scanner);
			break;

		case RRX_T:
		case ROR_T:
			sh = 0b11;
			token = next_token(scanner);
			token = next_token(scanner);
			break;
			
		default:
			break;
		}

		printf("%s\n", token_to_str(token.type));

		if (token.type == HASH_T) {
			
		} else if (token.type == INT_T) {
			shamt5 = token.val;
			int min = shift_type == LSL_T ?  0 :  1;
			int max = shift_type == LSL_T ? 31 : 32;
			
			if (shamt5 < min || shamt5 > max) {
				const char* shift_str = token_to_str(shift_type);
																									
				print_s(scanner->s, token.idx, token.len);
				printf("Shift amount %" PRIu32 "must be between %d-%d "
							 "(inclusive) for %s.\n", shamt5, min, max, shift_str);
				exit(EXIT_FAILURE);
			}
		}

		instr = set_shamt5(instr, shamt5);
		instr = set_sh(instr, sh);
		instr = set_Rm(instr, reg);
	}

  
  return instr;
}

// Parse instruction.
static Instr parse_instr(Scanner* scanner, Instr instr) {
  Token token;
  int reg;

  token = next_token(scanner);
	const char* instr_type_str = token_to_str(token.type);

  switch (token.type) {

  // Data Processing Instructions
  case ADD_T:
  case ADC_T:
  case SUB_T:
  case SBC_T:
  case RSB_T:
  case RSC_T:
		instr = set_cmd(instr, token_to_cmd(token));
		
    if (peek_token(scanner).type == S_T) {
      instr = set_S(instr);
      token = next_token(scanner);
    }

    Cond cond = AL;
    if (token_to_cond(peek_token(scanner), &cond))
      token = next_token(scanner);
    instr = set_cond(instr, cond);

    reg   = parse_reg(scanner);
    instr = set_Rd(instr, reg);

    token = expect_token(scanner, COMMA_T);

    reg   = parse_reg(scanner);
    instr = set_Rn(instr, reg);

    token = expect_token(scanner, COMMA_T);

    instr = parse_data_Src2(scanner, instr, instr_type_str);
    break;
  default:
    // TODO: handle errors
    break;
  }

  return instr;
}

int main(int argc, char** argv) {
  Scanner scanner;
  scanner_init(&scanner, argv[1]);
  
  Instr res = parse_instr(&scanner, 0);

  char res_bstr[BSTR_LEN];
  u32_to_bstr(res, res_bstr);
  printf("0b%s\n", res_bstr);

  char res_hstr[HSTR_LEN];
  u32_to_hstr(res, res_hstr);
  printf("0x%s\n", res_hstr);
    
  return EXIT_SUCCESS;
}
