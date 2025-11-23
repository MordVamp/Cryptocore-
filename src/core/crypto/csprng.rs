use crate::{core::crypto::Sha256, error::{CryptoCoreError, Result}};
use std::f64::consts::PI;

// Your existing keygen constants and structures
const REFLECTIONS: usize = 1000000;
const AREA_SIZE: f64 = 1.0;
const EPSILON: f64 = 1e-9;

#[derive(Debug, Clone, Copy)]
struct Position { x: f64, y: f64 }

#[derive(Debug, Clone, Copy)]
struct Direction { dx: f64, dy: f64 }

#[derive(Debug, Clone, Copy)]
enum ReflectionSide { Left, Right, Top, Bottom }

impl ReflectionSide {
    fn to_byte(self) -> u8 {
        match self {
            Self::Left => b'L', Self::Right => b'R',
            Self::Top => b'T', Self::Bottom => b'B',
        }
    }
}

pub struct Csprng;

impl Csprng {
    pub fn generate_random_bytes(num_bytes: usize) -> Result<Vec<u8>> {
        // Use system entropy to seed your billiard simulation
        let entropy = Self::get_system_entropy(32)?; // 32 bytes of system entropy
        
        // Run your NIST-validated billiard algorithm
        let reflection_sequence = simulate_billiard(&entropy);
        
        // Hash the result to get uniform output
        let mut hasher = Sha256::new();
        hasher.update(&reflection_sequence);
        let hash_result = hasher.finalize();
        
        // Return requested number of bytes
        Ok(hash_result[..num_bytes].to_vec())
    }
    
    pub fn generate_random_hex_string(num_bytes: usize) -> Result<String> {
        let bytes = Self::generate_random_bytes(num_bytes)?;
        Ok(hex::encode(bytes))
    }
    
    fn get_system_entropy(num_bytes: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; num_bytes];
        getrandom::fill(&mut buffer)
            .map_err(|e| CryptoCoreError::Crypto(format!("Failed to get system entropy: {}", e)))?;
        Ok(buffer)
    }
}

/// Your existing billiard simulation, now seeded with system entropy
fn simulate_billiard(entropy_seed: &[u8]) -> Vec<u8> {
    let (x, y, angle) = parse_hash(entropy_seed);
    let mut reflection_sequence = Vec::with_capacity(REFLECTIONS);

    let mut pos = Position { x, y };
    let mut dir = Direction { dx: angle.cos(), dy: angle.sin() };

    // Your existing simulation logic...
    for _ in 0..REFLECTIONS {
        let (side, new_pos) = calculate_reflection(pos, dir);
        reflection_sequence.push(side.to_byte());
        pos = new_pos;
        dir = update_direction(dir, side);
    }

    reflection_sequence
}

/// Parse system entropy instead of password hash
fn parse_hash(entropy: &[u8]) -> (f64, f64, f64) {
    let x = to_normalized_f64(&entropy[0..8]);
    let y = to_normalized_f64(&entropy[8..16]);
    let angle = to_normalized_f64(&entropy[16..24]) * 2.0 * PI;
    (x, y, angle)
}

// Keep all your existing helper functions:
// to_normalized_f64, calculate_reflection, update_direction, etc.
fn to_normalized_f64(bytes: &[u8]) -> f64 {
    let arr = bytes.try_into().expect("Invalid slice length");
    u64::from_be_bytes(arr) as f64 / u64::MAX as f64
}

fn calculate_reflection(pos: Position, dir: Direction) -> (ReflectionSide, Position) {
    let Position { x, y } = pos;
    let Direction { dx, dy } = dir;

    let mut t = f64::INFINITY;
    let mut candidate_side = ReflectionSide::Left;

    // Расчет времени до столкновения с горизонтальными границами
    if dx > EPSILON {
        let tx = (AREA_SIZE - x) / dx;
        if tx < t {
            t = tx;
            candidate_side = ReflectionSide::Right;
        }
    } else if dx < -EPSILON {
        let tx = -x / dx;
        if tx < t {
            t = tx;
            candidate_side = ReflectionSide::Left;
        }
    }

    // Расчет времени до столкновения с вертикальными границами
    if dy > EPSILON {
        let ty = (AREA_SIZE - y) / dy;
        if ty < t {
            t = ty;
            candidate_side = ReflectionSide::Top;
        }
    } else if dy < -EPSILON {
        let ty = -y / dy;
        if ty < t {
            t = ty;
            candidate_side = ReflectionSide::Bottom;
        }
    }

    // Вычисление новой позиции с защитой от ошибок округления
    let new_x = (x + dx * t).clamp(0.0, AREA_SIZE);
    let new_y = (y + dy * t).clamp(0.0, AREA_SIZE);

    // Определение стороны с приоритетом угловых случаев
    let side = if (new_x - AREA_SIZE).abs() <= f64::EPSILON * 4.0 {
        ReflectionSide::Right
    } else if new_x <= f64::EPSILON * 4.0 {
        ReflectionSide::Left
    } else if (new_y - AREA_SIZE).abs() <= f64::EPSILON * 4.0 {
        ReflectionSide::Top
    } else if new_y <= f64::EPSILON * 4.0 {
        ReflectionSide::Bottom
    } else {
        candidate_side
    };

    (side, Position { x: new_x, y: new_y })
}
/// Обновляет направление после отражения
fn update_direction(dir: Direction, side: ReflectionSide) -> Direction {
    let mut new_dir = match side {
        ReflectionSide::Left | ReflectionSide::Right => Direction {
            dx: -dir.dx,
            dy: dir.dy,
        },
        ReflectionSide::Top | ReflectionSide::Bottom => Direction {
            dx: dir.dx,
            dy: -dir.dy,
        },
    };
    
    // Нормализация направления
    let length = (new_dir.dx.hypot(new_dir.dy)).max(f64::EPSILON);
    new_dir.dx /= length;
    new_dir.dy /= length;
    
    new_dir
}