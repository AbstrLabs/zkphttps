# u8u32

This package allows you to convert u8 values to u32 and u32 to u8.

## Usage

Install this package with `leo add justice-league/u8u32` and then add this import to your `main.leo`:

```leo
import u8u32.(
    u32_u8,
    u8_u32
);

// here are ways to use this library
function main() {
    // u8 TO u32
    console.assert(u8_u32(10) == 10u32);
    
    // u32 TO u8
    console.assert(u32_u8(255) == 255u8);

    // it is also possible to write integers implicitly
    console.assert(u32_u8(100) == 100);
}
```

## Build Guide

To compile this Leo program, run:
```bash
leo build
```

To test this Leo program, run:
```bash
leo test
```

## Development

To output the number of constraints, run:
```bash
leo build -d
```
