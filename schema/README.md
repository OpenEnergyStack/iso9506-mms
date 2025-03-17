# Source ASN.1 Schema

<https://www.iso.org/committee/54192.html?view=documents> --> _ISO 9506 (MMS) ASN.1 Modules_ --> _MMS_

## `rasn` Compiler Errata

1. `CLASS` type definitions not supported
2. `DEFAULT` only supported for primative types. Setting default values for a `SEQUENCE` results in the entire definition being omitted with no error. E.g. `DEFAULT { fieldA 0, fieldB 99 }`
3. `DEFAULT` produces invalid Rust code for `CHOICE` with `<type>: <value>` syntax. E.g. `startCount [1] StartCount DEFAULT cycleCount: 1`
4. `DEFAULT` produces invalid Rust code for `BIT STRING`. `extendedStatusMask [2] IMPLICIT ExtendedStatus DEFAULT '1111'B` --> `ExtendedStatus([true, true, true, true].into_iter().collect())`
5. Comments between `CHOICE` items break parsing.
6. `SIZE()` is not interpreted correctly when `|` is used to specify individual sizes. E.g. `TimeOfDay ::= OCTET STRING (SIZE(4|6))` is interpreted as if it had `SIZE(4..6)` and `#[rasn(delegate, size("4..=6"))]` appears in the generated code.
7. Generated code `Debug` prints very verbose representation of bitvec types for `BitString` and `FixedBitString`. Define more concise debug output.
8. Tags should default to `EXPLICIT`, but do not. E.g `my-value [1] INTEGER` should be treated the same as `my-value [1] EXPLICIT INTEGER`.

## Creation of checked-in .asn schemas

1. Append `ISO-TC 184-SC 5_MMS Module_ACSE_ASN.htm` to `ISO-TC 184-SC 5_MMS.asn`.
2. Manually remove `CLASS` type definitions. These are not supported by `rasn-compiler`.
3. Run formatter to remove problemmatic comments and normalize formatting. This [web tool](https://osystest.site/webtools2/asn1SyntaxCheck.php) worked.
4. Replace `DEFAULT` values for constructed types such as `SEQUENCE` and `CHOICE` with `OPTIONAL`, as `rasn-compiler` only supports default values for primative types.
5. Replace `DEFAULT` values for `BIT STRING` with `OPTIONAL`, as invalid Rust code is generated.
6. Modules `IMPORT` `Authentication-value` from `MMS-Environment-1`, but it is defined in `ACSE-1`. Move it to `MMS-Environment-1` as expected.
7. Split each ASN.1 module into its own file for more convenient organization (optional). These files are checked in.
