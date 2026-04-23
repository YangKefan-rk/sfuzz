impl :: bincode :: Encode for SymExpr
{
    fn encode < __E : :: bincode :: enc :: Encoder >
    (& self, encoder : & mut __E) ->core :: result :: Result < (), :: bincode
    :: error :: EncodeError >
    {
        match self
        {
            Self ::InputByte { offset, value }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (0u32), encoder) ?
                ; :: bincode :: Encode :: encode(offset, encoder) ?; ::
                bincode :: Encode :: encode(value, encoder) ?; core :: result
                :: Result :: Ok(())
            }, Self ::Integer { value, bits }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (1u32), encoder) ?
                ; :: bincode :: Encode :: encode(value, encoder) ?; :: bincode
                :: Encode :: encode(bits, encoder) ?; core :: result :: Result
                :: Ok(())
            }, Self ::Integer128 { high, low }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (2u32), encoder) ?
                ; :: bincode :: Encode :: encode(high, encoder) ?; :: bincode
                :: Encode :: encode(low, encoder) ?; core :: result :: Result
                :: Ok(())
            }, Self ::IntegerFromBuffer {}
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (3u32), encoder) ?
                ; core :: result :: Result :: Ok(())
            }, Self ::Float { value, is_double }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (4u32), encoder) ?
                ; :: bincode :: Encode :: encode(value, encoder) ?; :: bincode
                :: Encode :: encode(is_double, encoder) ?; core :: result ::
                Result :: Ok(())
            }, Self ::NullPointer
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (5u32), encoder) ?
                ; core :: result :: Result :: Ok(())
            }, Self ::True
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (6u32), encoder) ?
                ; core :: result :: Result :: Ok(())
            }, Self ::False
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (7u32), encoder) ?
                ; core :: result :: Result :: Ok(())
            }, Self ::Bool { value }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (8u32), encoder) ?
                ; :: bincode :: Encode :: encode(value, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::Neg { op }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (9u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::Add { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (10u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Sub { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (11u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Mul { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (12u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::UnsignedDiv { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (13u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::SignedDiv { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (14u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::UnsignedRem { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (15u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::SignedRem { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (16u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::ShiftLeft { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (17u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::LogicalShiftRight { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (18u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::ArithmeticShiftRight { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (19u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::SignedLessThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (20u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::SignedLessEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (21u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::SignedGreaterThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (22u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::SignedGreaterEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (23u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::UnsignedLessThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (24u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::UnsignedLessEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (25u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::UnsignedGreaterThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (26u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::UnsignedGreaterEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (27u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Not { op }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (28u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::Equal { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (29u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::NotEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (30u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::BoolAnd { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (31u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::BoolOr { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (32u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::BoolXor { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (33u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::And { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (34u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Or { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (35u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Xor { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (36u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrdered { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (37u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrderedGreaterThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (38u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrderedGreaterEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (39u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrderedLessThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (40u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrderedLessEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (41u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrderedEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (42u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatOrderedNotEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (43u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnordered { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (44u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnorderedGreaterThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (45u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnorderedGreaterEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (46u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnorderedLessThan { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (47u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnorderedLessEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (48u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnorderedEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (49u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatUnorderedNotEqual { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (50u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatNeg { op }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (51u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::FloatAbs { op }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (52u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::FloatAdd { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (53u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatSub { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (54u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatMul { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (55u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatDiv { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (56u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatRem { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (57u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Ite { cond, a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (58u32), encoder) ?
                ; :: bincode :: Encode :: encode(cond, encoder) ?; :: bincode
                :: Encode :: encode(a, encoder) ?; :: bincode :: Encode ::
                encode(b, encoder) ?; core :: result :: Result :: Ok(())
            }, Self ::Sext { op, bits }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (59u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(bits, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Zext { op, bits }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (60u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(bits, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Trunc { op, bits }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (61u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(bits, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::IntToFloat { op, is_double, is_signed }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (62u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(is_double, encoder) ?; :: bincode :: Encode
                :: encode(is_signed, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatToFloat { op, to_double }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (63u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(to_double, encoder) ?; core :: result ::
                Result :: Ok(())
            }, Self ::BitsToFloat { op, to_double }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (64u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(to_double, encoder) ?; core :: result ::
                Result :: Ok(())
            }, Self ::FloatToBits { op }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (65u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::FloatToSignedInteger { op, bits }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (66u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(bits, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::FloatToUnsignedInteger { op, bits }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (67u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(bits, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::BoolToBit { op }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (68u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::Concat { a, b }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (69u32), encoder) ?
                ; :: bincode :: Encode :: encode(a, encoder) ?; :: bincode ::
                Encode :: encode(b, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Extract { op, first_bit, last_bit }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (70u32), encoder) ?
                ; :: bincode :: Encode :: encode(op, encoder) ?; :: bincode ::
                Encode :: encode(first_bit, encoder) ?; :: bincode :: Encode
                :: encode(last_bit, encoder) ?; core :: result :: Result ::
                Ok(())
            }, Self ::Insert { target, to_insert, offset, little_endian }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (71u32), encoder) ?
                ; :: bincode :: Encode :: encode(target, encoder) ?; ::
                bincode :: Encode :: encode(to_insert, encoder) ?; :: bincode
                :: Encode :: encode(offset, encoder) ?; :: bincode :: Encode
                :: encode(little_endian, encoder) ?; core :: result :: Result
                :: Ok(())
            }, Self ::PathConstraint { constraint, taken, location }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (72u32), encoder) ?
                ; :: bincode :: Encode :: encode(constraint, encoder) ?; ::
                bincode :: Encode :: encode(taken, encoder) ?; :: bincode ::
                Encode :: encode(location, encoder) ?; core :: result ::
                Result :: Ok(())
            }, Self ::ExpressionsUnreachable { exprs }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (73u32), encoder) ?
                ; :: bincode :: Encode :: encode(exprs, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::Call { location }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (74u32), encoder) ?
                ; :: bincode :: Encode :: encode(location, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::Return { location }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (75u32), encoder) ?
                ; :: bincode :: Encode :: encode(location, encoder) ?; core ::
                result :: Result :: Ok(())
            }, Self ::BasicBlock { location }
            =>{
                < u32 as :: bincode :: Encode >:: encode(& (76u32), encoder) ?
                ; :: bincode :: Encode :: encode(location, encoder) ?; core ::
                result :: Result :: Ok(())
            },
        }
    }
}