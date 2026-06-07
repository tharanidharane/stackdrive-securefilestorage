import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';
import './CustomSelect.css';

export default function CustomSelect({ value, onChange, options, disabled, style }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedOption = options.find(opt => opt.value === value) || options[0];

  return (
    <div 
      className={`custom-select-container ${disabled ? 'disabled' : ''}`} 
      ref={dropdownRef} 
      style={style}
    >
      <div 
        className={`custom-select-trigger ${isOpen ? 'open' : ''}`}
        onClick={() => !disabled && setIsOpen(!isOpen)}
      >
        <span>{selectedOption?.label}</span>
        <ChevronDown size={16} className={`chevron-icon ${isOpen ? 'open' : ''}`} />
      </div>
      {isOpen && (
        <div className="custom-select-options">
          {options.map((opt) => (
            <div 
              key={opt.value}
              className={`custom-select-option ${opt.value === value ? 'selected' : ''}`}
              onClick={() => {
                onChange({ target: { value: opt.value } });
                setIsOpen(false);
              }}
            >
              {opt.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
