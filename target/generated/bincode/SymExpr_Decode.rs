impl < __Context > :: bincode :: Decode < __Context > for SymExpr
{
    fn decode < __D : :: bincode :: de :: Decoder < Context = __Context > >
    (decoder : & mut __D) ->core :: result :: Result < Self, :: bincode ::
    error :: DecodeError >
    {
        let variant_index = < u32 as :: bincode :: Decode ::< __D :: Context
        >>:: decode(decoder) ?; match variant_index
        {
            0u32 =>core :: result :: Result ::
            Ok(Self ::InputByte
            {
                offset : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, value : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 1u32 =>core :: result :: Result ::
            Ok(Self ::Integer
            {
                value : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, bits : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 2u32 =>core :: result :: Result ::
            Ok(Self ::Integer128
            {
                high : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, low : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 3u32 =>core :: result :: Result ::
            Ok(Self ::IntegerFromBuffer {}), 4u32 =>core :: result :: Result
            ::
            Ok(Self ::Float
            {
                value : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, is_double : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 5u32 =>core :: result :: Result :: Ok(Self ::NullPointer {}),
            6u32 =>core :: result :: Result :: Ok(Self ::True {}), 7u32 =>core
            :: result :: Result :: Ok(Self ::False {}), 8u32 =>core :: result
            :: Result ::
            Ok(Self ::Bool
            {
                value : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 9u32 =>core :: result :: Result ::
            Ok(Self ::Neg
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 10u32 =>core :: result :: Result ::
            Ok(Self ::Add
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 11u32 =>core :: result :: Result ::
            Ok(Self ::Sub
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 12u32 =>core :: result :: Result ::
            Ok(Self ::Mul
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 13u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedDiv
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 14u32 =>core :: result :: Result ::
            Ok(Self ::SignedDiv
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 15u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedRem
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 16u32 =>core :: result :: Result ::
            Ok(Self ::SignedRem
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 17u32 =>core :: result :: Result ::
            Ok(Self ::ShiftLeft
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 18u32 =>core :: result :: Result ::
            Ok(Self ::LogicalShiftRight
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 19u32 =>core :: result :: Result ::
            Ok(Self ::ArithmeticShiftRight
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 20u32 =>core :: result :: Result ::
            Ok(Self ::SignedLessThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 21u32 =>core :: result :: Result ::
            Ok(Self ::SignedLessEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 22u32 =>core :: result :: Result ::
            Ok(Self ::SignedGreaterThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 23u32 =>core :: result :: Result ::
            Ok(Self ::SignedGreaterEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 24u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedLessThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 25u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedLessEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 26u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedGreaterThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 27u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedGreaterEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 28u32 =>core :: result :: Result ::
            Ok(Self ::Not
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 29u32 =>core :: result :: Result ::
            Ok(Self ::Equal
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 30u32 =>core :: result :: Result ::
            Ok(Self ::NotEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 31u32 =>core :: result :: Result ::
            Ok(Self ::BoolAnd
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 32u32 =>core :: result :: Result ::
            Ok(Self ::BoolOr
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 33u32 =>core :: result :: Result ::
            Ok(Self ::BoolXor
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 34u32 =>core :: result :: Result ::
            Ok(Self ::And
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 35u32 =>core :: result :: Result ::
            Ok(Self ::Or
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 36u32 =>core :: result :: Result ::
            Ok(Self ::Xor
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 37u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrdered
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 38u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedGreaterThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 39u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedGreaterEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 40u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedLessThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 41u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedLessEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 42u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 43u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedNotEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 44u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnordered
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 45u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedGreaterThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 46u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedGreaterEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 47u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedLessThan
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 48u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedLessEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 49u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 50u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedNotEqual
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 51u32 =>core :: result :: Result ::
            Ok(Self ::FloatNeg
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 52u32 =>core :: result :: Result ::
            Ok(Self ::FloatAbs
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 53u32 =>core :: result :: Result ::
            Ok(Self ::FloatAdd
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 54u32 =>core :: result :: Result ::
            Ok(Self ::FloatSub
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 55u32 =>core :: result :: Result ::
            Ok(Self ::FloatMul
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 56u32 =>core :: result :: Result ::
            Ok(Self ::FloatDiv
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 57u32 =>core :: result :: Result ::
            Ok(Self ::FloatRem
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 58u32 =>core :: result :: Result ::
            Ok(Self ::Ite
            {
                cond : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, a : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?, b : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 59u32 =>core :: result :: Result ::
            Ok(Self ::Sext
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, bits : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 60u32 =>core :: result :: Result ::
            Ok(Self ::Zext
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, bits : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 61u32 =>core :: result :: Result ::
            Ok(Self ::Trunc
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, bits : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 62u32 =>core :: result :: Result ::
            Ok(Self ::IntToFloat
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, is_double : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?, is_signed : :: bincode ::
                Decode ::< __D :: Context >:: decode(decoder) ?,
            }), 63u32 =>core :: result :: Result ::
            Ok(Self ::FloatToFloat
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, to_double : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 64u32 =>core :: result :: Result ::
            Ok(Self ::BitsToFloat
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, to_double : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 65u32 =>core :: result :: Result ::
            Ok(Self ::FloatToBits
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 66u32 =>core :: result :: Result ::
            Ok(Self ::FloatToSignedInteger
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, bits : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 67u32 =>core :: result :: Result ::
            Ok(Self ::FloatToUnsignedInteger
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, bits : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?,
            }), 68u32 =>core :: result :: Result ::
            Ok(Self ::BoolToBit
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 69u32 =>core :: result :: Result ::
            Ok(Self ::Concat
            {
                a : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, b : :: bincode :: Decode ::< __D :: Context
                >:: decode(decoder) ?,
            }), 70u32 =>core :: result :: Result ::
            Ok(Self ::Extract
            {
                op : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, first_bit : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?, last_bit : :: bincode :: Decode
                ::< __D :: Context >:: decode(decoder) ?,
            }), 71u32 =>core :: result :: Result ::
            Ok(Self ::Insert
            {
                target : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, to_insert : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?, offset : :: bincode :: Decode
                ::< __D :: Context >:: decode(decoder) ?, little_endian : ::
                bincode :: Decode ::< __D :: Context >:: decode(decoder) ?,
            }), 72u32 =>core :: result :: Result ::
            Ok(Self ::PathConstraint
            {
                constraint : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?, taken : :: bincode :: Decode ::< __D ::
                Context >:: decode(decoder) ?, location : :: bincode :: Decode
                ::< __D :: Context >:: decode(decoder) ?,
            }), 73u32 =>core :: result :: Result ::
            Ok(Self ::ExpressionsUnreachable
            {
                exprs : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 74u32 =>core :: result :: Result ::
            Ok(Self ::Call
            {
                location : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 75u32 =>core :: result :: Result ::
            Ok(Self ::Return
            {
                location : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), 76u32 =>core :: result :: Result ::
            Ok(Self ::BasicBlock
            {
                location : :: bincode :: Decode ::< __D :: Context >::
                decode(decoder) ?,
            }), variant =>core :: result :: Result ::
            Err(:: bincode :: error :: DecodeError :: UnexpectedVariant
            {
                found : variant, type_name : "SymExpr", allowed : &:: bincode
                :: error :: AllowedEnumVariants :: Range { min: 0, max: 76 }
            })
        }
    }
} impl < '__de, __Context > :: bincode :: BorrowDecode < '__de, __Context >
for SymExpr
{
    fn borrow_decode < __D : :: bincode :: de :: BorrowDecoder < '__de,
    Context = __Context > > (decoder : & mut __D) ->core :: result :: Result <
    Self, :: bincode :: error :: DecodeError >
    {
        let variant_index = < u32 as :: bincode :: Decode ::< __D :: Context
        >>:: decode(decoder) ?; match variant_index
        {
            0u32 =>core :: result :: Result ::
            Ok(Self ::InputByte
            {
                offset : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, value : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 1u32 =>core :: result :: Result ::
            Ok(Self ::Integer
            {
                value : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, bits : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 2u32 =>core :: result :: Result ::
            Ok(Self ::Integer128
            {
                high : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, low : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 3u32 =>core :: result :: Result ::
            Ok(Self ::IntegerFromBuffer {}), 4u32 =>core :: result :: Result
            ::
            Ok(Self ::Float
            {
                value : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, is_double : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 5u32 =>core :: result :: Result :: Ok(Self ::NullPointer {}),
            6u32 =>core :: result :: Result :: Ok(Self ::True {}), 7u32 =>core
            :: result :: Result :: Ok(Self ::False {}), 8u32 =>core :: result
            :: Result ::
            Ok(Self ::Bool
            {
                value : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 9u32 =>core :: result :: Result ::
            Ok(Self ::Neg
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 10u32 =>core :: result :: Result ::
            Ok(Self ::Add
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 11u32 =>core :: result :: Result ::
            Ok(Self ::Sub
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 12u32 =>core :: result :: Result ::
            Ok(Self ::Mul
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 13u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedDiv
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 14u32 =>core :: result :: Result ::
            Ok(Self ::SignedDiv
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 15u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedRem
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 16u32 =>core :: result :: Result ::
            Ok(Self ::SignedRem
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 17u32 =>core :: result :: Result ::
            Ok(Self ::ShiftLeft
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 18u32 =>core :: result :: Result ::
            Ok(Self ::LogicalShiftRight
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 19u32 =>core :: result :: Result ::
            Ok(Self ::ArithmeticShiftRight
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 20u32 =>core :: result :: Result ::
            Ok(Self ::SignedLessThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 21u32 =>core :: result :: Result ::
            Ok(Self ::SignedLessEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 22u32 =>core :: result :: Result ::
            Ok(Self ::SignedGreaterThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 23u32 =>core :: result :: Result ::
            Ok(Self ::SignedGreaterEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 24u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedLessThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 25u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedLessEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 26u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedGreaterThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 27u32 =>core :: result :: Result ::
            Ok(Self ::UnsignedGreaterEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 28u32 =>core :: result :: Result ::
            Ok(Self ::Not
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 29u32 =>core :: result :: Result ::
            Ok(Self ::Equal
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 30u32 =>core :: result :: Result ::
            Ok(Self ::NotEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 31u32 =>core :: result :: Result ::
            Ok(Self ::BoolAnd
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 32u32 =>core :: result :: Result ::
            Ok(Self ::BoolOr
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 33u32 =>core :: result :: Result ::
            Ok(Self ::BoolXor
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 34u32 =>core :: result :: Result ::
            Ok(Self ::And
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 35u32 =>core :: result :: Result ::
            Ok(Self ::Or
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 36u32 =>core :: result :: Result ::
            Ok(Self ::Xor
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 37u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrdered
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 38u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedGreaterThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 39u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedGreaterEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 40u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedLessThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 41u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedLessEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 42u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 43u32 =>core :: result :: Result ::
            Ok(Self ::FloatOrderedNotEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 44u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnordered
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 45u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedGreaterThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 46u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedGreaterEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 47u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedLessThan
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 48u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedLessEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 49u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 50u32 =>core :: result :: Result ::
            Ok(Self ::FloatUnorderedNotEqual
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 51u32 =>core :: result :: Result ::
            Ok(Self ::FloatNeg
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 52u32 =>core :: result :: Result ::
            Ok(Self ::FloatAbs
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 53u32 =>core :: result :: Result ::
            Ok(Self ::FloatAdd
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 54u32 =>core :: result :: Result ::
            Ok(Self ::FloatSub
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 55u32 =>core :: result :: Result ::
            Ok(Self ::FloatMul
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 56u32 =>core :: result :: Result ::
            Ok(Self ::FloatDiv
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 57u32 =>core :: result :: Result ::
            Ok(Self ::FloatRem
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 58u32 =>core :: result :: Result ::
            Ok(Self ::Ite
            {
                cond : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, a : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?, b : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 59u32 =>core :: result :: Result ::
            Ok(Self ::Sext
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, bits : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 60u32 =>core :: result :: Result ::
            Ok(Self ::Zext
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, bits : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 61u32 =>core :: result :: Result ::
            Ok(Self ::Trunc
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, bits : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 62u32 =>core :: result :: Result ::
            Ok(Self ::IntToFloat
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, is_double : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
                is_signed : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 63u32 =>core :: result :: Result ::
            Ok(Self ::FloatToFloat
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, to_double : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 64u32 =>core :: result :: Result ::
            Ok(Self ::BitsToFloat
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, to_double : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 65u32 =>core :: result :: Result ::
            Ok(Self ::FloatToBits
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 66u32 =>core :: result :: Result ::
            Ok(Self ::FloatToSignedInteger
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, bits : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 67u32 =>core :: result :: Result ::
            Ok(Self ::FloatToUnsignedInteger
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, bits : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 68u32 =>core :: result :: Result ::
            Ok(Self ::BoolToBit
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 69u32 =>core :: result :: Result ::
            Ok(Self ::Concat
            {
                a : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, b : :: bincode :: BorrowDecode ::<
                __D :: Context >:: borrow_decode(decoder) ?,
            }), 70u32 =>core :: result :: Result ::
            Ok(Self ::Extract
            {
                op : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, first_bit : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
                last_bit : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 71u32 =>core :: result :: Result ::
            Ok(Self ::Insert
            {
                target : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, to_insert : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
                offset : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, little_endian : :: bincode ::
                BorrowDecode ::< __D :: Context >:: borrow_decode(decoder) ?,
            }), 72u32 =>core :: result :: Result ::
            Ok(Self ::PathConstraint
            {
                constraint : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?, taken : :: bincode :: BorrowDecode
                ::< __D :: Context >:: borrow_decode(decoder) ?, location : ::
                bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 73u32 =>core :: result :: Result ::
            Ok(Self ::ExpressionsUnreachable
            {
                exprs : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 74u32 =>core :: result :: Result ::
            Ok(Self ::Call
            {
                location : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 75u32 =>core :: result :: Result ::
            Ok(Self ::Return
            {
                location : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), 76u32 =>core :: result :: Result ::
            Ok(Self ::BasicBlock
            {
                location : :: bincode :: BorrowDecode ::< __D :: Context >::
                borrow_decode(decoder) ?,
            }), variant =>core :: result :: Result ::
            Err(:: bincode :: error :: DecodeError :: UnexpectedVariant
            {
                found : variant, type_name : "SymExpr", allowed : &:: bincode
                :: error :: AllowedEnumVariants :: Range { min: 0, max: 76 }
            })
        }
    }
}