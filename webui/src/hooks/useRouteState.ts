import { useRouter } from 'next/router';
import { useCallback, useEffect, useState } from 'react';

interface UseRouteStateOptions {
  param: string;
  defaultValue?: string;
  validValues?: string[];
}

/**
 * 自定义Hook用于管理URL参数状态
 * 自动同步组件状态和URL参数
 */
export function useRouteState<T extends string>({
  param,
  defaultValue,
  validValues
}: UseRouteStateOptions) {
  const router = useRouter();
  const [value, setValue] = useState<T | undefined>(defaultValue as T);

  // 从URL参数初始化状态
  useEffect(() => {
    if (!router.isReady) return;

    const urlValue = router.query[param] as string;
    
    if (urlValue) {
      if (validValues && !validValues.includes(urlValue)) {
        // 无效值，重定向到默认值
        const newQuery = { ...router.query };
        if (defaultValue) {
          newQuery[param] = defaultValue;
        } else {
          delete newQuery[param];
        }
        router.replace({ 
          pathname: router.pathname, 
          query: newQuery 
        }, undefined, { shallow: true });
        setValue(defaultValue as T);
      } else {
        setValue(urlValue as T);
      }
    } else {
      setValue(defaultValue as T);
    }
  }, [router.isReady, router.query, param, defaultValue, validValues, router]);

  // 更新URL参数的函数
  const updateValue = useCallback((newValue: T | undefined) => {
    if (newValue === value) return; // 避免重复更新

    setValue(newValue);

    const newQuery = { ...router.query };
    if (newValue && newValue !== defaultValue) {
      newQuery[param] = newValue;
    } else {
      delete newQuery[param];
    }

    router.replace({
      pathname: router.pathname,
      query: newQuery
    }, undefined, { shallow: true });
  }, [value, router, param, defaultValue]);

  return [value, updateValue] as const;
}

/**
 * 用于管理主页标签状态的专用Hook
 */
export function useTabState() {
  return useRouteState({
    param: 'tab',
    defaultValue: 'upload',
    validValues: ['upload', 'history', 'active']
  });
}

/**
 * 用于管理Graph页面任务ID的专用Hook
 */
export function useGraphTaskState() {
  return useRouteState({
    param: 'taskId'
  });
}

/**
 * 导航辅助函数
 */
export function useNavigation() {
  const router = useRouter();

  const goBack = useCallback(() => {
    if (window.history.length > 1) {
      router.back();
    } else {
      router.push('/');
    }
  }, [router]);

  const goHome = useCallback((tab?: 'upload' | 'history' | 'active') => {
    const url = tab && tab !== 'upload' ? `/?tab=${tab}` : '/';
    router.push(url);
  }, [router]);

  const goToGraph = useCallback((taskId?: string) => {
    const url = taskId ? `/graph?taskId=${taskId}` : '/graph';
    router.push(url);
  }, [router]);

  return {
    goBack,
    goHome,
    goToGraph,
    currentPath: router.pathname,
    query: router.query
  };
}