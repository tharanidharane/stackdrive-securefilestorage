import React from 'react';

export default function LogoIcon({ size = '100%', className = '' }) {
  return (
    <img 
      src="/logo.png" 
      alt="StackDrive Logo" 
      width={size} 
      height={size} 
      className={className} 
      style={{ 
        objectFit: 'contain', 
        display: 'block', 
        mixBlendMode: 'screen' 
      }}
    />
  );
}
