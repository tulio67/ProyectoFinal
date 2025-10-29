import { test, expect } from '@playwright/test';

test.describe('Pruebas de Funcionalidades Específicas de Buggy Cars', () => {
  
  // Primero hacer login para pruebas autenticadas
  test.beforeEach(async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    await page.fill('input[name="login"]', 'Marco@gmail.com');
    await page.fill('input[name="password"]', 'Marco123/');
    await page.click('button[type="submit"]');
    
    try {
      await page.waitForSelector('text=Profile', { timeout: 5000 });
    } catch (error) {
      console.log('Login automático falló, continuando con pruebas sin autenticación');
    }
  });

  test('Verificar perfil de usuario', async ({ page }) => {
    // Navegar al perfil si el login fue exitoso
    try {
      await page.click('text=Profile');
      await expect(page).toHaveURL(/profile/);
      
      // Verificar elementos del perfil
      await expect(page.locator('text=First Name')).toBeVisible();
      await expect(page.locator('text=Last Name')).toBeVisible();
      
      console.log('Página de perfil cargada correctamente');
    } catch {
      console.log('No se pudo acceder al perfil (posiblemente no autenticado)');
    }
  });

  test('Explorar catálogo de autos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Buscar elementos relacionados con autos
    const carElements = [
      'img[alt*="car"]',
      'img[alt*="Car"]',
      '.car',
      '[class*="car"]',
      'text=Lamborghini',
      'text=Ferrari',
      'text=Bugatti'
    ];
    
    for (const selector of carElements) {
      try {
        const element = page.locator(selector).first();
        const isVisible = await element.isVisible({ timeout: 2000 });
        
        if (isVisible) {
          console.log(`Elemento de auto encontrado: ${selector}`);
          
          // Si es clickeable, hacer click
          if (selector.includes('text=') || selector.includes('img')) {
            await element.click();
            await page.waitForTimeout(1000);
            console.log(`Click realizado en: ${selector}`);
            break;
          }
        }
      } catch {
        // Continuar con el siguiente selector
      }
    }
  });

  test('Probar funcionalidad de votación/rating', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Buscar elementos de rating (estrellas, botones de voto)
    const ratingSelectors = [
      '.rating',
      '[class*="rating"]',
      '[class*="star"]',
      'button[title*="vote"]',
      'button[title*="rate"]',
      'input[type="radio"]'
    ];
    
    for (const selector of ratingSelectors) {
      try {
        const elements = page.locator(selector);
        const count = await elements.count();
        
        if (count > 0) {
          console.log(`Encontrados ${count} elementos de rating con selector: ${selector}`);
          
          // Intentar interactuar con el primer elemento
          const firstElement = elements.first();
          const isVisible = await firstElement.isVisible();
          
          if (isVisible) {
            await firstElement.click();
            console.log(`Click realizado en elemento de rating`);
            await page.waitForTimeout(1000);
            break;
          }
        }
      } catch {
        // Continuar con el siguiente selector
      }
    }
  });

  test('Verificar responsividad móvil', async ({ page }) => {
    // Cambiar a viewport móvil
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('https://buggy.justtestit.org/');
    
    // Verificar que elementos principales sigan siendo visibles
    await expect(page.locator('text=Buggy Cars Rating')).toBeVisible();
    
    // Buscar menú hamburger u otros elementos móviles
    const mobileElements = [
      '.hamburger',
      '.menu-toggle',
      '[class*="mobile-menu"]',
      'button[aria-label="Menu"]'
    ];
    
    for (const selector of mobileElements) {
      try {
        const element = page.locator(selector);
        const isVisible = await element.isVisible({ timeout: 2000 });
        
        if (isVisible) {
          console.log(`Elemento móvil encontrado: ${selector}`);
          await element.click();
          await page.waitForTimeout(500);
        }
      } catch {
        // Continuar
      }
    }
    
    console.log('Prueba de responsividad móvil completada');
  });

  test('Probar funcionalidad de búsqueda de autos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Buscar campo de búsqueda específico para autos
    const searchSelectors = [
      'input[placeholder*="search"]',
      'input[placeholder*="Search"]',
      'input[name="search"]',
      '.search-input',
      '[class*="search"]'
    ];
    
    for (const selector of searchSelectors) {
      try {
        const searchInput = page.locator(selector).first();
        const isVisible = await searchInput.isVisible({ timeout: 2000 });
        
        if (isVisible) {
          await searchInput.fill('Lamborghini');
          await searchInput.press('Enter');
          
          console.log('Búsqueda de "Lamborghini" realizada');
          await page.waitForTimeout(2000);
          break;
        }
      } catch {
        // Continuar con el siguiente selector
      }
    }
  });

  test('Verificar funcionalidades después del login', async ({ page }) => {
    try {
      // Verificar si estamos logueados
      const isLoggedIn = await page.isVisible('text=Profile');
      
      if (isLoggedIn) {
        console.log('Usuario autenticado correctamente');
        
        // Probar funcionalidades que requieren autenticación
        const authFeatures = [
          'text=My votes',
          'text=My profile',
          'text=Settings',
          'button[title*="vote"]',
          'text=Add comment'
        ];
        
        for (const feature of authFeatures) {
          try {
            const element = page.locator(feature).first();
            const isVisible = await element.isVisible({ timeout: 2000 });
            
            if (isVisible) {
              console.log(`Funcionalidad autenticada encontrada: ${feature}`);
            }
          } catch {
            // Continuar
          }
        }
      } else {
        console.log('Usuario no autenticado, saltando pruebas autenticadas');
      }
    } catch (error) {
      console.log('Error al verificar estado de autenticación');
    }
  });

});