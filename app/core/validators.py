"""
SentinelPay – Shared input validation utilities.
"""

from decimal import Decimal


def validate_monetary_amount(amount: Decimal, max_limit: Decimal = Decimal("10000000.00")) -> Decimal:
    """Validate that monetary input:
    - Is a finite, valid number (not NaN, not Infinity)
    - Is strictly positive (> 0.00)
    - Does not exceed a sane maximum limit
    - Does not have more than 2 decimal places
    """
    if amount.is_nan() or amount.is_infinite():
        raise ValueError("Amount must be a valid finite number")

    if amount <= Decimal("0.00"):
        raise ValueError("Amount must be strictly positive")

    if amount > max_limit:
        raise ValueError(f"Amount exceeds maximum allowed limit of {max_limit}")

    # Exponent < -2 means more than 2 decimal places (e.g. 10.001 has exponent -3)
    if amount.as_tuple().exponent < -2:
        raise ValueError("Amount cannot have more than 2 decimal places")

    return amount
